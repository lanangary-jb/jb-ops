<?php
/**
 * Plugin Name: JB Ops Bridge
 * Description: JuiceBox Ops Bridge — a secured, structured REST endpoint for AI-assisted site/DB inspection and controlled changes. Reads and writes are allowlisted ops; writes are dry-run by default and need a confirm_token to apply, and each applied write returns a revert_token. The wp-admin UI is visible only to JuiceBox staff (logged-in admins on a juicebox.co.id / juicebox.com.au email).
 * Version: 0.9.2
 * Author: JuiceBox
 *
 * SECURITY MODEL
 * --------------
 *  - Inert by default. Does nothing until explicitly enabled (constant or option).
 *  - Token-gated: every request needs a bearer token compared with hash_equals().
 *  - Structured ops only: no raw SQL / no eval. The AI composes allowlisted operations.
 *  - Reads are always available when enabled; WRITES are behind a separate toggle and
 *    are dry-run by default — applying needs a one-time confirm_token from the dry run,
 *    and each applied write returns a single-use revert_token (stored in a durable table,
 *    not a transient). Catastrophic options and user-table writes are blocked outright.
 *  - Every write passes one central gate (gate_write): writes-toggle, fail-closed audit,
 *    optional IP allowlist, per-op tier (core/extended/danger), optional per-op allowlist,
 *    optional rate limit. Danger-tier ops need a separate toggle AND an allowlist entry.
 *  - FILE WRITES (write_file) are danger-tier and scoped to wp-content (themes/plugins);
 *    they refuse secret/config files, the .git/uploads/cache dirs, and the JB Ops plugin's
 *    own directory. Dry-run shows a diff; apply returns a revert_token that restores the
 *    prior content (or deletes a newly-created file). No file write touches WP core.
 *  - Sensitive option/meta values are redacted (key pattern + value heuristic) before they
 *    leave the site or are written to the audit log.
 *  - Every call (read, dry_run, applied, reverted) is written to an audit table.
 *  - The admin pages (Dashboard + Settings) are visible only to logged-in site
 *    administrators (manage_options) whose email is on an allowed JuiceBox domain
 *    (juicebox.co.id / juicebox.com.au; filterable via 'jb_ops_allowed_email_domains').
 *    Everyone else sees no menu. The REST bridge is unaffected — it authenticates by
 *    token and has no logged-in user.
 *
 * CONFIG
 *  All settings live in the plugin — no wp-config / .env changes.
 *  wp-admin -> JB Ops -> Settings: enable + auto-generate a token.
 *  Stored in option h_ops_settings (default: disabled). Settings are bound to the
 *  site URL they were saved on, so an enabled state can't follow a DB copy (wp-sync-db)
 *  to another environment.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'H_OPS_VERSION', '0.11.0' );
define( 'H_OPS_NS', 'h-ops/v1' );

/**
 * Ed25519 PUBLIC key (base64) for the access token. SAFE to ship in every copy: a public key can
 * VERIFY the daily-rotating signed token (jb1.<UTCdate>.<sig>) but cannot FORGE one. The matching
 * PRIVATE key is held only by the operator, off-site — never in this repository or on any site.
 * A request bearing a valid signature is fully trusted (reads + writes + export), with no per-site
 * wp-admin setup — so deploying the plugin is all it takes. Set to '' to disable signed auth and
 * fall back to the manual enable + per-site token model.
 */
if ( ! defined( 'H_OPS_SIGNING_PUBKEY' ) ) {
	define( 'H_OPS_SIGNING_PUBKEY', '/oRLcscuQkM/NK7z/rj0j225ALh6cQ8Ih8OhjrxD2SU=' );
}
/** Context string mixed into the signed message, so the key can't be cross-used for another purpose. */
define( 'H_OPS_SIGN_CONTEXT', 'h-ops-v1:' );

class H_Ops_Bridge {

	/** @var array<string,array> op registry: name => [type, cb|preview|apply, args, desc] */
	private $ops = array();

	/** True once the current request has been authenticated by a valid fleet signature (full trust). */
	private $signed = false;

	/** A confirm_token from a dry run is valid for this long. */
	const CONFIRM_TTL = 300;        // 5 minutes
	/** A revert_token (undo of an applied write) is valid for this long. */
	const REVERT_TTL  = 86400;      // 24 hours
	/** Largest file write_file will accept (decoded bytes). Keeps revert backups sane. */
	const MAX_WRITE_BYTES = 8388608; // 8 MB
	/** A DB-export download link (GET /export/{token}) is valid for this long, then it's pruned. */
	const EXPORT_TTL   = 3600;   // 1 hour
	/** Rows read+written per chunk while dumping a table (streamed, never all in memory at once). */
	const EXPORT_BATCH = 2000;

	public function __construct() {
		$this->register_ops();
		add_action( 'rest_api_init', array( $this, 'register_routes' ) );
		// In-place version upgrades (file deploy, not (re)activation) still get the tables.
		add_action( 'plugins_loaded', array( $this, 'maybe_upgrade' ) );
		if ( is_admin() ) {
			add_action( 'admin_menu', array( $this, 'admin_menu' ) );
			add_action( 'admin_post_h_ops_save', array( $this, 'handle_admin_save' ) );
			add_action( 'admin_post_h_ops_clear_log', array( $this, 'handle_clear_log' ) );
			add_action( 'admin_init', array( $this, 'maybe_cleanup_active_plugins' ) );
		}
	}

	/**
	 * Self-heal after a regular-plugin -> mu-plugin conversion. When this file runs from
	 * mu-plugins but a stale 'jb-ops/jb-ops.php' still lingers in active_plugins (left over
	 * from when it was a normal plugin), WP would otherwise warn "plugin file does not exist".
	 * Drop the stale entry. No wp-cli/DB access needed; runs at most once.
	 */
	public function maybe_cleanup_active_plugins() {
		if ( false === strpos( str_replace( '\\', '/', __FILE__ ), '/mu-plugins/' ) ) {
			return; // only relevant when loaded as a must-use plugin
		}
		$active = (array) get_option( 'active_plugins', array() );
		$self   = 'jb-ops/jb-ops.php';
		if ( in_array( $self, $active, true ) ) {
			update_option( 'active_plugins', array_values( array_diff( $active, array( $self ) ) ) );
		}
	}

	/* ---------------------------------------------------------------------
	 * Config
	 * ------------------------------------------------------------------- */

	private function settings() {
		$opt = get_option( 'h_ops_settings', array() );
		return is_array( $opt ) ? $opt : array();
	}

	private function is_enabled() {
		$s = $this->settings();
		if ( empty( $s['enabled'] ) ) {
			return false;
		}
		// Site-binding guard: settings are saved against the site they were enabled on.
		// If this DB is synced to a different site (wp-sync-db), the URLs won't match and
		// the bridge stays OFF until someone re-enables it here. No env config needed.
		if ( ! empty( $s['site'] ) && $this->norm_url( $s['site'] ) !== $this->norm_url( home_url() ) ) {
			return false;
		}
		return true;
	}

	private function site_mismatch() {
		$s = $this->settings();
		return ! empty( $s['enabled'] ) && ! empty( $s['site'] ) && $this->norm_url( $s['site'] ) !== $this->norm_url( home_url() );
	}

	private function norm_url( $u ) {
		return untrailingslashit( preg_replace( '#^https?://#', '', (string) $u ) );
	}

	private function token() {
		$s = $this->settings();
		return isset( $s['token'] ) ? (string) $s['token'] : '';
	}

	/** Writes require: a fleet signature (full trust), OR bridge enabled + a deliberate write toggle. */
	private function writes_enabled() {
		if ( $this->signed ) {
			return true;
		}
		$s = $this->settings();
		return $this->is_enabled() && ! empty( $s['writes_enabled'] );
	}

	/**
	 * Admin pages are restricted to site administrators (manage_options) who are also
	 * logged in on an allowed JuiceBox email domain. The REST bridge is unaffected — it
	 * authenticates by token and has no logged-in user, so this gate never touches the API.
	 */
	private function admin_allowed() {
		return current_user_can( 'manage_options' ) && $this->is_juicebox_user();
	}

	/**
	 * True when the current user's email is on an allowed JuiceBox domain. The list is
	 * filterable (jb_ops_allowed_email_domains) so it can be extended without code edits.
	 */
	private function is_juicebox_user() {
		$user = wp_get_current_user();
		if ( ! $user || ! $user->exists() ) {
			return false;
		}
		$email = strtolower( trim( (string) $user->user_email ) );
		$at    = strrpos( $email, '@' );
		if ( false === $at ) {
			return false;
		}
		$domain  = substr( $email, $at + 1 );
		$allowed = apply_filters( 'jb_ops_allowed_email_domains', array( 'juicebox.co.id', 'juicebox.com.au' ) );
		$allowed = array_map( 'strtolower', array_filter( (array) $allowed ) );
		return in_array( $domain, $allowed, true );
	}

	/* ---------------------------------------------------------------------
	 * Routing + auth
	 * ------------------------------------------------------------------- */

	public function register_routes() {
		register_rest_route( H_OPS_NS, '/ping', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'handle_ping' ),
			'permission_callback' => array( $this, 'authorize' ),
		) );
		register_rest_route( H_OPS_NS, '/ops', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'handle_ops' ),
			'permission_callback' => array( $this, 'authorize' ),
		) );
		register_rest_route( H_OPS_NS, '/run', array(
			'methods'             => 'POST',
			'callback'            => array( $this, 'handle_run' ),
			'permission_callback' => array( $this, 'authorize' ),
		) );
		// One-time download of a generated DB export. Bearer-gated like everything else, so the
		// unguessable token in the URL is a second factor, not the only one. Streams the gz file
		// then deletes it (single use). The {token} pattern keeps WP from matching junk paths.
		register_rest_route( H_OPS_NS, '/export/(?P<token>[a-f0-9]{32,64})', array(
			'methods'             => 'GET',
			'callback'            => array( $this, 'handle_export_download' ),
			'permission_callback' => array( $this, 'authorize' ),
		) );
	}

	/**
	 * Permission callback. The token is the credential — no WP login required,
	 * which is what lets an AI session call it. We still refuse unless enabled.
	 */
	public function authorize( WP_REST_Request $request ) {
		$given = $this->bearer( $request );

		// Preferred path: a fleet-signed, daily-rotating token (jb1.<date>.<sig>). It is
		// unforgeable without the JuiceBox private key, so it authenticates with ZERO per-site
		// config — the bridge works the moment the plugin is deployed, no "enable" step needed.
		if ( $given && $this->verify_signed_token( $given ) ) {
			$this->signed = true;
			return true;
		}

		// Fallback: the legacy enable + per-site static token model (manual setup in Settings).
		if ( ! $this->is_enabled() ) {
			return new WP_Error( 'h_ops_disabled', 'JB Ops Bridge is disabled (no valid fleet signature, and the manual endpoint is off).', array( 'status' => 403 ) );
		}
		$expected = $this->token();
		if ( strlen( $expected ) < 16 ) {
			return new WP_Error( 'h_ops_misconfigured', 'JB Ops token missing or too short (need >= 16 chars).', array( 'status' => 500 ) );
		}
		if ( ! $given || ! hash_equals( $expected, $given ) ) {
			return new WP_Error( 'h_ops_unauthorized', 'Invalid or missing token.', array( 'status' => 401 ) );
		}
		return true;
	}

	/**
	 * Verify a fleet-signed access token: format jb1.<UTCdate:Ymd>.<base64url Ed25519 signature>.
	 * The signature must cover H_OPS_SIGN_CONTEXT.<date> under the embedded public key, and the
	 * date must be within +/-1 day of the server's UTC date (grace for clock skew / timezones).
	 * Daily rotation falls out of this: a token's date drifts out of the window after ~a day, so a
	 * captured token expires on its own. Returns false (never throws) so a bad token just 401s.
	 */
	private function verify_signed_token( $token ) {
		$pub_b64 = ( defined( 'H_OPS_SIGNING_PUBKEY' ) && H_OPS_SIGNING_PUBKEY ) ? (string) H_OPS_SIGNING_PUBKEY : '';
		if ( '' === $pub_b64 || ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return false; // signed auth not configured / sodium missing -> use the fallback path
		}
		if ( ! preg_match( '/^jb1\.([0-9]{8})\.([A-Za-z0-9_-]+)$/', (string) $token, $m ) ) {
			return false;
		}
		$date = $m[1];
		$sig  = $this->b64url_decode( $m[2] );
		$pk   = base64_decode( $pub_b64, true );
		if ( false === $sig || false === $pk
			|| SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig )
			|| SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pk ) ) {
			return false;
		}
		// Freshness window: token date must be yesterday / today / tomorrow (UTC).
		$allowed = array(
			gmdate( 'Ymd', time() - DAY_IN_SECONDS ),
			gmdate( 'Ymd' ),
			gmdate( 'Ymd', time() + DAY_IN_SECONDS ),
		);
		if ( ! in_array( $date, $allowed, true ) ) {
			return false;
		}
		return sodium_crypto_sign_verify_detached( $sig, H_OPS_SIGN_CONTEXT . $date, $pk );
	}

	/** URL-safe base64 decode (accepts -_ and missing padding). Returns false on garbage. */
	private function b64url_decode( $s ) {
		$s   = strtr( (string) $s, '-_', '+/' );
		$pad = strlen( $s ) % 4;
		if ( $pad ) {
			$s .= str_repeat( '=', 4 - $pad );
		}
		return base64_decode( $s, true );
	}

	private function bearer( WP_REST_Request $request ) {
		$auth = $request->get_header( 'authorization' );
		if ( $auth && stripos( $auth, 'bearer ' ) === 0 ) {
			return trim( substr( $auth, 7 ) );
		}
		$hdr = $request->get_header( 'x_h_ops_token' );
		return $hdr ? trim( $hdr ) : '';
	}

	/* ---------------------------------------------------------------------
	 * Write gating (defence-in-depth, enforced before any preview/apply)
	 * ------------------------------------------------------------------- */

	/** Tier of a write op (core | extended | danger). Defaults FAIL-SAFE: destructive-verb names => danger. */
	private function op_tier( $def, $op = '' ) {
		if ( isset( $def['tier'] ) && in_array( $def['tier'], array( 'core', 'extended', 'danger' ), true ) ) {
			return $def['tier'];
		}
		// A write op with a destructive-sounding name that forgot to declare a tier is treated as danger.
		if ( '' !== $op && preg_match( '/^(delete_|force_|destroy_|drop_|install_|activate_|deactivate_|switch_theme|update_plugin|update_theme|run_cron|merge_|reset_|set_user_|create_user)/', $op ) ) {
			return 'danger';
		}
		return 'core';
	}

	/**
	 * Central write gate, run BEFORE preview/apply. The token is the only credential, so every
	 * deliberate switch lives here. Returns true to allow, or array{code,message,status} to refuse.
	 */
	private function gate_write( $op, $def ) {
		// A fleet-signed request is fully trusted: it bypasses the per-site write/danger/export
		// toggles, the per-op allowlist, IP allowlist and rate limit (that's the zero-config
		// "always on for JuiceBox" behaviour). It still must be auditable (fail-closed below), and
		// every write still runs dry-run -> confirm_token -> revert_token, so the operational
		// safety net is unchanged — only the AUTHORIZATION toggles are short-circuited.
		if ( $this->signed ) {
			if ( '' === $this->log_table() ) {
				return array( 'code' => 'audit_unavailable', 'message' => 'Audit log table is missing; writes are refused until tables exist.', 'status' => 503 );
			}
			return true;
		}
		if ( ! $this->writes_enabled() ) {
			return array( 'code' => 'writes_disabled', 'message' => 'Write operations are disabled. Turn them on in Settings -> JB Ops Bridge.', 'status' => 403 );
		}
		// Fail-closed: never apply a write we cannot audit.
		if ( '' === $this->log_table() ) {
			return array( 'code' => 'audit_unavailable', 'message' => 'Audit log table is missing; writes are refused until the plugin is re-activated.', 'status' => 503 );
		}
		$s     = $this->settings();
		$allow = ( isset( $s['allowed_ops'] ) && is_array( $s['allowed_ops'] ) ) ? $s['allowed_ops'] : array();

		// Optional IP allowlist (off when empty).
		$ip = $this->check_ip_allowlist( $s );
		if ( true !== $ip ) {
			return $ip;
		}
		// Danger-tier ops need a separate, deliberate toggle AND an explicit per-op allowlist entry.
		if ( 'danger' === $this->op_tier( $def, $op ) ) {
			$dg = $this->danger_gate( $op, $s );
			if ( true !== $dg ) {
				return $dg;
			}
		}
		// A full DB export bypasses the per-value redaction every other read applies (it ships
		// password hashes, API keys and PII verbatim), so it sits behind its OWN deliberate toggle
		// on top of the danger gate above — being danger-tier alone is not enough.
		if ( ! empty( $def['needs_export_toggle'] ) && empty( $s['export_enabled'] ) ) {
			return array( 'code' => 'export_disabled', 'message' => 'Database export is disabled. Enable "Allow database export" in Settings (it includes secrets/PII with no redaction).', 'status' => 403 );
		}
		// Optional per-op allowlist: when non-empty, ONLY listed ops may run.
		if ( ! empty( $allow ) && ! in_array( $op, $allow, true ) ) {
			return array( 'code' => 'op_not_allowlisted', 'message' => 'Operation "' . $op . '" is not in the per-op allowlist.', 'status' => 403 );
		}
		// Optional write rate limit (off when 0).
		$rl = $this->check_rate_limit( $s );
		if ( true !== $rl ) {
			return $rl;
		}
		return true;
	}

	/** Optional IP allowlist. true = allowed; array = refusal. Empty list = feature off. */
	private function check_ip_allowlist( $s ) {
		$list = isset( $s['ip_allowlist'] ) ? trim( (string) $s['ip_allowlist'] ) : '';
		if ( '' === $list ) {
			return true;
		}
		$ip = $this->client_ip();
		foreach ( preg_split( '/[\s,]+/', $list ) as $entry ) {
			$entry = trim( $entry );
			if ( '' !== $entry && $this->ip_matches( $ip, $entry ) ) {
				return true;
			}
		}
		return array( 'code' => 'ip_blocked', 'message' => 'Your IP is not on the allowlist.', 'status' => 403 );
	}

	/** Exact IP or IPv4 CIDR match (best-effort). */
	private function ip_matches( $ip, $entry ) {
		if ( false === strpos( $entry, '/' ) ) {
			return $ip === $entry;
		}
		list( $subnet, $bits ) = array_pad( explode( '/', $entry, 2 ), 2, '' );
		$ipl  = ip2long( $ip );
		$sub  = ip2long( $subnet );
		$bits = (int) $bits;
		if ( false === $ipl || false === $sub || $bits < 0 || $bits > 32 ) {
			return false;
		}
		$mask = ( 0 === $bits ) ? 0 : ( -1 << ( 32 - $bits ) );
		return ( $ipl & $mask ) === ( $sub & $mask );
	}

	/** Optional per-token write rate limit. true = allowed; array = refusal. 0 = off. */
	private function check_rate_limit( $s ) {
		$max = isset( $s['rate_limit'] ) ? absint( $s['rate_limit'] ) : 0;
		if ( $max < 1 ) {
			return true;
		}
		$key   = 'h_ops_rl_' . md5( $this->token() );
		$count = (int) get_transient( $key );
		if ( $count >= $max ) {
			return array( 'code' => 'rate_limited', 'message' => 'Write rate limit reached (' . $max . '/min). Try again shortly.', 'status' => 429 );
		}
		set_transient( $key, $count + 1, MINUTE_IN_SECONDS );
		return true;
	}

	/** Danger-tier authorisation: requires the allow_danger toggle AND the op on the per-op allowlist. */
	private function danger_gate( $op, $s ) {
		if ( empty( $s['allow_danger'] ) ) {
			return array( 'code' => 'danger_disabled', 'message' => 'This is a danger-tier operation; enable "Allow danger operations" in Settings to use it.', 'status' => 403 );
		}
		$allow = ( isset( $s['allowed_ops'] ) && is_array( $s['allowed_ops'] ) ) ? $s['allowed_ops'] : array();
		if ( $op && ! in_array( $op, $allow, true ) ) {
			return array( 'code' => 'danger_needs_allowlist', 'message' => 'Danger-tier operation "' . $op . '" must be in the per-op allowlist in Settings.', 'status' => 403 );
		}
		return true;
	}
	/** Whether a revert payload represents the inverse of a danger-tier op (so revert must clear the danger gate too). */
	private function revert_is_danger( $payload, $op ) {
		// Intrinsically-danger payload types: recognised by TYPE alone, so the danger gate
		// still applies even when the op name was lost (e.g. the transient fallback path of
		// take_revert returns op=''). 'file' = the inverse of write_file (RCE-class).
		if ( in_array( ( isset( $payload['type'] ) ? $payload['type'] : '' ), array( 'plugin_state', 'file' ), true ) ) {
			return true;
		}
		return $op && isset( $this->ops[ $op ] ) && 'danger' === $this->op_tier( $this->ops[ $op ], $op );
	}

	/* ---------------------------------------------------------------------
	 * Endpoint handlers
	 * ------------------------------------------------------------------- */

	public function handle_ping( WP_REST_Request $request ) {
		return $this->ok( 'ping', array(
			'plugin_version' => H_OPS_VERSION,
			'site_url'       => site_url(),
			'home_url'       => home_url(),
			'wp_version'     => get_bloginfo( 'version' ),
			'writes_enabled' => $this->writes_enabled(),
			'time'           => current_time( 'mysql' ),
		) );
	}

	public function handle_ops( WP_REST_Request $request ) {
		$list = array();
		foreach ( $this->ops as $name => $def ) {
			$list[] = array(
				'op'   => $name,
				'type' => $def['type'],
				'args' => $def['args'],
				'desc' => $def['desc'],
			);
		}
		return $this->ok( 'ops', array( 'operations' => $list ) );
	}

	public function handle_run( WP_REST_Request $request ) {
		$body = $request->get_json_params();
		if ( ! is_array( $body ) ) {
			$body = $request->get_params();
		}
		$op   = isset( $body['op'] ) ? sanitize_key( $body['op'] ) : '';
		$args = isset( $body['args'] ) && is_array( $body['args'] ) ? $body['args'] : array();

		if ( 'revert' === $op ) {
			return $this->run_revert( $args );
		}
		if ( ! isset( $this->ops[ $op ] ) ) {
			return $this->fail( $op, 'unknown_op', 'Unknown operation. GET /ops for the list.', 400 );
		}
		$def = $this->ops[ $op ];

		if ( 'read' === $def['type'] ) {
			$start = microtime( true );
			try {
				$data = call_user_func( $def['cb'], $args );
			} catch ( \Throwable $e ) {
				$this->audit( $op, $args, 'error', array( 'message' => $e->getMessage() ) );
				return $this->fail( $op, 'op_exception', $e->getMessage(), 500 );
			}
			$took     = (int) round( ( microtime( true ) - $start ) * 1000 );
			$audit_id = $this->audit( $op, $args, 'ok', array( 'took_ms' => $took ) );
			return $this->ok( $op, $data, array( 'took_ms' => $took, 'audit_id' => $audit_id ) );
		}

		/* ----- write op: gate -> dry-run -> confirm -> apply ----- */
		$gate = $this->gate_write( $op, $def );
		if ( true !== $gate ) {
			return $this->fail( $op, $gate['code'], $gate['message'], $gate['status'] );
		}

		try {
			$preview = call_user_func( $def['preview'], $args ); // [before, after, would_change, summary, revert]
		} catch ( \Throwable $e ) {
			return $this->fail( $op, 'preview_error', $e->getMessage(), 400 );
		}

		// Writes default to dry-run. Only an explicit dry_run:false proceeds to apply.
		$is_real = isset( $body['dry_run'] ) && false === $body['dry_run'];

		if ( ! $is_real ) {
			$confirm = $this->store_confirm( $op, $args );
			$this->audit( $op, $args, 'dry_run', array( 'would_change' => ! empty( $preview['would_change'] ), 'summary' => $preview['summary'] ?? '' ) );
			return $this->ok(
				$op,
				array( 'diff' => $this->public_diff( $preview ) ),
				array( 'confirm_token' => $confirm, 'expires_in' => self::CONFIRM_TTL,
					'note' => 'Re-send with "dry_run": false and this confirm_token to apply.' ),
				true
			);
		}

		$confirm_token = isset( $body['confirm_token'] ) ? (string) $body['confirm_token'] : '';
		$check = $this->check_confirm( $confirm_token, $op, $args );
		if ( true !== $check ) {
			return $this->fail( $op, 'confirm_required', $check, 409 );
		}

		try {
			$result = call_user_func( $def['apply'], $args, $preview );
		} catch ( \Throwable $e ) {
			$this->audit( $op, $args, 'error', array( 'message' => $e->getMessage() ) );
			return $this->fail( $op, 'apply_error', $e->getMessage(), 500 );
		}

		// Apply may refine the revert payload (e.g. create_post needs the new post id).
		$revert_payload = $preview['revert'] ?? null;
		if ( is_array( $result ) && array_key_exists( '_revert', $result ) ) {
			$revert_payload = $result['_revert'];
			unset( $result['_revert'] );
		}
		$revert_token = ! empty( $revert_payload ) ? $this->store_revert( $revert_payload, $op ) : null;
		$audit_id     = $this->audit( $op, $args, 'applied', array( 'summary' => $preview['summary'] ?? '', 'would_change' => ! empty( $preview['would_change'] ) ) );

		return $this->ok(
			$op,
			array( 'applied' => true, 'diff' => $this->public_diff( $preview ), 'result' => $result ),
			array( 'audit_id' => $audit_id, 'revert_token' => $revert_token, 'revert_expires_in' => self::REVERT_TTL ),
			false
		);
	}

	/** Undo a previously applied write using its revert_token. */
	private function run_revert( $args ) {
		if ( ! $this->writes_enabled() ) {
			return $this->fail( 'revert', 'writes_disabled', 'Write operations are disabled.', 403 );
		}
		if ( '' === $this->log_table() ) {
			return $this->fail( 'revert', 'audit_unavailable', 'Audit log table is missing; revert is refused until the plugin is re-activated.', 503 );
		}
		$ip = $this->check_ip_allowlist( $this->settings() );
		if ( true !== $ip ) {
			return $this->fail( 'revert', $ip['code'], $ip['message'], $ip['status'] );
		}
		$token = isset( $args['revert_token'] ) ? (string) $args['revert_token'] : '';
		if ( 32 !== strlen( $token ) || ! ctype_xdigit( $token ) ) {
			return $this->fail( 'revert', 'token_required', 'A valid revert_token is required.', 400 );
		}
		$rv = $this->take_revert( $token );
		if ( ! is_array( $rv ) ) {
			return $this->fail( 'revert', 'token_invalid', 'revert_token invalid, already used, or expired.', 409 );
		}
		$payload = $rv['payload'];
		$rev_op  = (string) $rv['op'];
		// A danger-tier revert is the INVERSE of a danger op and is equally dangerous — gate it the
		// same way, unless the request is fleet-signed (fully trusted, like gate_write above).
		if ( ! $this->signed && $this->revert_is_danger( $payload, $rev_op ) ) {
			$dg = $this->danger_gate( $rev_op, $this->settings() );
			if ( true !== $dg ) {
				return $this->fail( 'revert', $dg['code'], $dg['message'], $dg['status'] );
			}
		}
		try {
			$this->restore( $payload );
		} catch ( \Throwable $e ) {
			return $this->fail( 'revert', 'revert_error', $e->getMessage(), 500 );
		}
		// Do NOT echo the payload back (it holds raw before-values) — report only the type.
		$audit_id = $this->audit( 'revert', array(), 'reverted', array( 'type' => $payload['type'] ?? '' ) );
		return $this->ok( 'revert', array( 'reverted' => true, 'type' => $payload['type'] ?? '' ), array( 'audit_id' => $audit_id ), false );
	}

	/** Fetch + consume a revert payload (single use): durable table first, transient fallback. */
	private function take_revert( $token ) {
		global $wpdb;
		$table = $this->revert_table();
		if ( '' !== $table ) {
			$now = gmdate( 'Y-m-d H:i:s', time() );
			// Atomically CLAIM the token: only ONE concurrent caller can flip used 0->1 on a live row.
			$claimed = $wpdb->query( $wpdb->prepare( "UPDATE $table SET used = 1 WHERE token = %s AND used = 0 AND expires >= %s", $token, $now ) );
			if ( 1 === (int) $claimed ) {
				$row = $wpdb->get_row( $wpdb->prepare( "SELECT payload, op FROM $table WHERE token = %s", $token ) );
				$p   = $row ? json_decode( (string) $row->payload, true ) : null;
				return is_array( $p ) ? array( 'payload' => $p, 'op' => $row->op ) : null;
			}
			// Row exists but is already used/expired -> do NOT fall through to the transient path.
			if ( $wpdb->get_var( $wpdb->prepare( "SELECT 1 FROM $table WHERE token = %s", $token ) ) ) {
				return null;
			}
		}
		// Fallback for tokens issued before the durable table existed.
		$p = get_transient( 'h_ops_rv_' . $token );
		if ( is_array( $p ) ) {
			delete_transient( 'h_ops_rv_' . $token );
			return array( 'payload' => $p, 'op' => '' );
		}
		return null;
	}

	/* ---------------------------------------------------------------------
	 * Operation registry (v1 = read only)
	 * ------------------------------------------------------------------- */

	private function register_ops() {
		$this->ops = array(
			'describe_site' => array(
				'type' => 'read', 'cb' => array( $this, 'op_describe_site' ), 'args' => array(),
				'desc' => 'Active theme, active plugins, multisite flag, permalink structure.',
			),
			'get_post' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_post' ), 'args' => array( 'id*' ),
				'desc' => 'Single post: core fields, permalink, parent, status.',
			),
			'query_posts' => array(
				'type' => 'read', 'cb' => array( $this, 'op_query_posts' ),
				'args' => array( 'post_type', 'post_status', 'name', 'search', 'meta_key', 'meta_value', 'limit', 'offset', 'orderby' ),
				'desc' => 'List posts (limit capped at 100). Returns id, title, type, status, name, parent, permalink.',
			),
			'get_post_meta' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_post_meta' ), 'args' => array( 'id*', 'key' ),
				'desc' => 'Post meta (single key or all). Sensitive values redacted.',
			),
			'get_option' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_option' ), 'args' => array( 'name*' ),
				'desc' => 'A single option value. Sensitive values redacted; output size capped.',
			),
			'list_options' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_options' ), 'args' => array( 'search', 'limit' ),
				'desc' => 'Option NAMES only (no values) matching a search string. For discovery.',
			),
			'permalink_manager_uris' => array(
				'type' => 'read', 'cb' => array( $this, 'op_pm_uris' ), 'args' => array( 'search', 'post_id' ),
				'desc' => 'Permalink Manager custom URIs (the permalink-manager-uris option), filterable.',
			),
			'list_redirects' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_redirects' ), 'args' => array( 'contains' ),
				'desc' => 'Redirect rules from Rank Math and the Redirection plugin, filterable by substring.',
			),
			'rewrite_rules' => array(
				'type' => 'read', 'cb' => array( $this, 'op_rewrite_rules' ), 'args' => array( 'match' ),
				'desc' => 'Registered rewrite rules (regex => query), optional substring filter.',
			),
			'resolve_url' => array(
				'type' => 'read', 'cb' => array( $this, 'op_resolve_url' ), 'args' => array( 'url*' ),
				'desc' => 'Best-effort: which post a front-end URL maps to + any redirect rule that matches it.',
			),
			'db_tables' => array(
				'type' => 'read', 'cb' => array( $this, 'op_db_tables' ), 'args' => array(),
				'desc' => 'List DB tables with approximate row counts.',
			),
			'get_user' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_user' ), 'args' => array( 'id', 'email', 'login', 'slug', 'include_meta' ),
				'desc' => 'A single user by id/email/login/slug: safe profile fields, roles, and (by default) their user-meta. Password hash + activation key never returned; other values redacted.',
			),
			'get_user_meta' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_user_meta' ), 'args' => array( 'user_id*', 'key' ),
				'desc' => 'User meta for one user (single key or all). Sensitive values redacted; auth material never returned.',
			),
			'usermeta_keys' => array(
				'type' => 'read', 'cb' => array( $this, 'op_usermeta_keys' ), 'args' => array( 'meta_key', 'limit' ),
				'desc' => 'Distribution of user-meta keys across the usermeta table (each key: row count + distinct users). Keys only, no values. The fast way to spot a meta_key that has disappeared.',
			),
			'list_files' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_files' ), 'args' => array( 'path', 'recursive', 'ext', 'max' ),
				'desc' => 'List files/dirs under a code path (default = active theme). Scoped to wp-content + core; secrets/uploads/.git blocked.',
			),
			'read_file' => array(
				'type' => 'read', 'cb' => array( $this, 'op_read_file' ), 'args' => array( 'path*', 'start_line', 'lines' ),
				'desc' => 'Read a source file (optionally a line range). Same scope/blocklist as list_files.',
			),
			'search_files' => array(
				'type' => 'read', 'cb' => array( $this, 'op_search_files' ), 'args' => array( 'pattern*', 'path', 'ext', 'regex', 'max_matches' ),
				'desc' => 'Grep code for a string/regex (file:line:excerpt). Great for finding hard-coded redirects.',
			),
			'write_file' => array(
				'type' => 'write', 'tier' => 'danger',
				'args' => array( 'path*', 'content', 'content_base64', 'create_dirs', 'overwrite' ),
				'preview' => array( $this, 'pv_write_file' ), 'apply' => array( $this, 'ap_write_file' ),
				'desc' => 'Create or replace a file under wp-content (themes/plugins). Pass UTF-8 "content" or binary "content_base64"; optional create_dirs, overwrite (default true). Danger-tier (needs the danger toggle + allowlist). Refuses WP core, secret/config files (wp-config/.env/keys/*.sql), the .git/uploads/cache dirs, and the JB Ops plugin dir. Dry-run returns a size/sha1 diff; apply returns a revert_token that restores the prior content (or deletes a newly-created file).',
			),
			'export_db' => array(
				'type' => 'write', 'tier' => 'danger', 'needs_export_toggle' => true,
				'args' => array( 'tables', 'all_tables', 'search', 'replace' ),
				'preview' => array( $this, 'pv_export_db' ), 'apply' => array( $this, 'ap_export_db' ),
				'desc' => 'Export the database to a gzipped SQL dump for standing up a local copy. Danger-tier AND requires the separate "Allow database export" toggle — a full dump ships secrets/PII with NO redaction. Optional serialize-safe "search"/"replace" (e.g. live URL => local URL, rewritten inside serialized data too). Scope: "tables" (comma/array) limits to specific tables; "all_tables":true dumps every table; default = tables matching this install\'s prefix. Dry-run reports table count + approx size; apply writes the dump to a protected uploads dir and returns a one-time, bearer-gated download_token — GET /export/{token} streams it, expires in 1h, and deletes on first download. The returned revert_token deletes the dump early.',
			),

			/* ----- write ops (dry-run by default; need confirm_token to apply) ----- */
			'update_post_meta' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'key*', 'value*' ),
				'preview' => array( $this, 'pv_update_post_meta' ), 'apply' => array( $this, 'ap_update_post_meta' ),
				'desc' => 'Set a single post meta value.',
			),
			'delete_post_meta' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'key*' ),
				'preview' => array( $this, 'pv_delete_post_meta' ), 'apply' => array( $this, 'ap_delete_post_meta' ),
				'desc' => 'Delete a single post meta key.',
			),
			'update_option' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'name*', 'value*' ),
				'preview' => array( $this, 'pv_update_option' ), 'apply' => array( $this, 'ap_update_option' ),
				'desc' => 'Set an option value (catastrophic options are blocked).',
			),
			'update_post_field' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'field*', 'value*' ),
				'preview' => array( $this, 'pv_update_post_field' ), 'apply' => array( $this, 'ap_update_post_field' ),
				'desc' => 'Update a whitelisted post field: post_status, post_name, post_parent, post_title, post_excerpt, post_content.',
			),
			'create_post' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'post_title*', 'post_type', 'post_status', 'post_content', 'post_excerpt', 'post_name', 'post_parent', 'post_author' ),
				'preview' => array( $this, 'pv_create_post' ), 'apply' => array( $this, 'ap_create_post' ),
				'desc' => 'Create a new post/page/CPT. Defaults: post_type=post, post_status=draft. Revert trashes the created post.',
			),

			'trash_post' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*' ),
				'preview' => array( $this, 'pv_trash_post' ), 'apply' => array( $this, 'ap_trash_post' ),
				'desc' => 'Move a post to the trash (recoverable). Refused if trash is disabled site-wide or on the front/posts page.',
			),
			'untrash_post' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*' ),
				'preview' => array( $this, 'pv_untrash_post' ), 'apply' => array( $this, 'ap_untrash_post' ),
				'desc' => 'Restore a post from the trash to its previous status.',
			),
			'publish_post' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*' ),
				'preview' => array( $this, 'pv_publish_post' ), 'apply' => array( $this, 'ap_publish_post' ),
				'desc' => 'Publish a draft/pending/private/scheduled post.',
			),
			'unpublish_post' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'to_status' ),
				'preview' => array( $this, 'pv_unpublish_post' ), 'apply' => array( $this, 'ap_unpublish_post' ),
				'desc' => 'Take a published post offline. to_status: draft (default), pending, or private.',
			),
			'set_featured_image' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'attachment_id*' ),
				'preview' => array( $this, 'pv_set_featured_image' ), 'apply' => array( $this, 'ap_set_featured_image' ),
				'desc' => 'Set (attachment_id of an image) or clear (0) a post featured image.',
			),
			'set_page_template' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'template*' ),
				'preview' => array( $this, 'pv_set_page_template' ), 'apply' => array( $this, 'ap_set_page_template' ),
				'desc' => 'Assign a theme page template filename (validated) or "default" to reset.',
			),
			'set_post_format' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'format*' ),
				'preview' => array( $this, 'pv_set_post_format' ), 'apply' => array( $this, 'ap_set_post_format' ),
				'desc' => 'Set a post format (standard|aside|gallery|link|image|quote|status|video|audio|chat).',
			),
			'set_sticky' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'sticky*' ),
				'preview' => array( $this, 'pv_set_sticky' ), 'apply' => array( $this, 'ap_set_sticky' ),
				'desc' => 'Pin/unpin a post on the blog homepage (sticky: true/false).',
			),
			'set_menu_order' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'menu_order*' ),
				'preview' => array( $this, 'pv_set_menu_order' ), 'apply' => array( $this, 'ap_set_menu_order' ),
				'desc' => 'Set a post menu_order (manual sort index for pages / ordered CPTs).',
			),

			'get_term' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_term' ), 'args' => array( 'term_id*', 'taxonomy' ),
				'desc' => 'Single term: name, slug, taxonomy, parent, count, description.',
			),
			'list_terms' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_terms' ), 'args' => array( 'taxonomy*', 'search', 'parent', 'hide_empty', 'include', 'exclude', 'orderby', 'limit', 'offset' ),
				'desc' => 'List terms in a taxonomy (limit capped at 200; hide_empty defaults false).',
			),
			'get_object_terms' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_object_terms' ), 'args' => array( 'object_id*', 'taxonomy*' ),
				'desc' => 'Terms currently assigned to a post/object in a taxonomy.',
			),
			'get_term_meta' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_term_meta' ), 'args' => array( 'term_id*', 'key' ),
				'desc' => 'Term meta (single key or all). Sensitive values redacted.',
			),
			'list_taxonomies' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_taxonomies' ), 'args' => array( 'object_type', 'public_only' ),
				'desc' => 'Registered taxonomies with labels, hierarchical/public flags, object types.',
			),
			'create_term' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'taxonomy*', 'name*', 'slug', 'parent', 'description' ),
				'preview' => array( $this, 'pv_create_term' ), 'apply' => array( $this, 'ap_create_term' ),
				'desc' => 'Create a term in an existing taxonomy. Revert deletes the new term.',
			),
			'update_term' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'term_id*', 'taxonomy*', 'name', 'description', 'parent' ),
				'preview' => array( $this, 'pv_update_term' ), 'apply' => array( $this, 'ap_update_term' ),
				'desc' => 'Update a term name/description/parent (not slug). Cycle-guarded.',
			),
			'set_term_parent' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'term_id*', 'taxonomy*', 'parent*' ),
				'preview' => array( $this, 'pv_set_term_parent' ), 'apply' => array( $this, 'ap_set_term_parent' ),
				'desc' => 'Set/clear a hierarchical term parent (0 = top level). Cycle-guarded.',
			),
			'set_post_terms' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'object_id*', 'taxonomy*', 'terms*', 'append' ),
				'preview' => array( $this, 'pv_set_post_terms' ), 'apply' => array( $this, 'ap_set_post_terms' ),
				'desc' => 'Set (replace) or append a posts terms in one taxonomy. terms = array of integer term_ids.',
			),
			'remove_post_terms' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'object_id*', 'taxonomy*', 'terms*' ),
				'preview' => array( $this, 'pv_remove_post_terms' ), 'apply' => array( $this, 'ap_remove_post_terms' ),
				'desc' => 'Remove specific terms (term_ids) from a post, leaving its others intact.',
			),

			'get_theme_mods' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_theme_mods' ), 'args' => array( 'theme' ),
				'desc' => 'All theme mods (customizer values) for the active or named theme. Sensitive values redacted.',
			),
			'get_settings_overview' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_settings_overview' ), 'args' => array(),
				'desc' => 'General/Reading/Discussion settings snapshot; resolves front-page ids to titles.',
			),
			'set_site_identity' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'title', 'tagline' ),
				'preview' => array( $this, 'pv_set_site_identity' ), 'apply' => array( $this, 'ap_set_site_identity' ),
				'desc' => 'Set site title (blogname) and/or tagline (blogdescription).',
			),
			'set_site_logo' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'attachment_id*' ),
				'preview' => array( $this, 'pv_set_site_logo' ), 'apply' => array( $this, 'ap_set_site_logo' ),
				'desc' => 'Set (image attachment_id) or clear (0) the theme custom logo.',
			),
			'set_site_icon' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'attachment_id*' ),
				'preview' => array( $this, 'pv_set_site_icon' ), 'apply' => array( $this, 'ap_set_site_icon' ),
				'desc' => 'Set (image attachment_id) or clear (0) the Site Icon / favicon.',
			),
			'update_theme_mod' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'key*', 'value*', 'theme' ),
				'preview' => array( $this, 'pv_update_theme_mod' ), 'apply' => array( $this, 'ap_update_theme_mod' ),
				'desc' => 'Set a single theme mod (customizer value) on the active or named theme.',
			),
			'delete_theme_mod' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'key*', 'theme' ),
				'preview' => array( $this, 'pv_delete_theme_mod' ), 'apply' => array( $this, 'ap_delete_theme_mod' ),
				'desc' => 'Remove a single theme mod (reverts it to the theme default).',
			),
			'set_timezone' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'timezone_string', 'gmt_offset' ),
				'preview' => array( $this, 'pv_set_timezone' ), 'apply' => array( $this, 'ap_set_timezone' ),
				'desc' => 'Set site timezone by IANA zone (preferred) or numeric UTC offset (sets one, clears the other).',
			),
			'set_date_time_format' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'date_format', 'time_format', 'start_of_week' ),
				'preview' => array( $this, 'pv_set_date_time_format' ), 'apply' => array( $this, 'ap_set_date_time_format' ),
				'desc' => 'Set date_format, time_format and/or start_of_week (0-6).',
			),
			'set_discussion_settings' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'default_comment_status', 'default_ping_status', 'comment_registration', 'comment_moderation', 'comment_previously_approved', 'comments_per_page', 'close_comments_for_old_posts', 'close_comments_days_old' ),
				'preview' => array( $this, 'pv_set_discussion_settings' ), 'apply' => array( $this, 'ap_set_discussion_settings' ),
				'desc' => 'Configure default comment/ping status and moderation policy (affects new posts/defaults).',
			),

			'list_nav_menus' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_nav_menus' ), 'args' => array(),
				'desc' => 'Nav menus (id, name, slug, item count) + registered locations and current assignments.',
			),
			'get_nav_menu' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_nav_menu' ), 'args' => array( 'menu*' ),
				'desc' => 'Full structure of one menu (items capped at 500). menu = term_id, slug, or name.',
			),
			'list_sidebars' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_sidebars' ), 'args' => array(),
				'desc' => 'Registered sidebars + their widget ids; reports whether block-widgets mode is active.',
			),
			'get_widget' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_widget' ), 'args' => array( 'widget_id*' ),
				'desc' => 'One widget instance settings (e.g. "text-3"). Sensitive values redacted.',
			),
			'list_synced_blocks' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_synced_blocks' ), 'args' => array( 'search' ),
				'desc' => 'Reusable/synced blocks (wp_block): id, title, slug, status.',
			),
			'create_nav_menu' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'name*' ),
				'preview' => array( $this, 'pv_create_nav_menu' ), 'apply' => array( $this, 'ap_create_nav_menu' ),
				'desc' => 'Create a new (empty) nav menu. Revert deletes the menu (and any items later added to it).',
			),
			'rename_nav_menu' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'menu*', 'name*' ),
				'preview' => array( $this, 'pv_rename_nav_menu' ), 'apply' => array( $this, 'ap_rename_nav_menu' ),
				'desc' => 'Rename an existing nav menu (items untouched).',
			),
			'add_nav_menu_item' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'menu*', 'title*', 'item_type', 'object_id', 'object', 'url', 'parent_item_id', 'position' ),
				'preview' => array( $this, 'pv_add_nav_menu_item' ), 'apply' => array( $this, 'ap_add_nav_menu_item' ),
				'desc' => 'Add a menu item (custom link or post_type/taxonomy/post_type_archive ref). Revert removes the new item.',
			),
			'create_synced_block' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'title*', 'content*' ),
				'preview' => array( $this, 'pv_create_synced_block' ), 'apply' => array( $this, 'ap_create_synced_block' ),
				'desc' => 'Create a reusable/synced block (wp_block, published). Revert trashes it.',
			),

			'get_field' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_field' ), 'args' => array( 'post_id*', 'selector*', 'format_value' ),
				'desc' => 'Read one ACF field value (formatted or raw). post_id accepts an id or term_X/user_X/option. Redacted.',
			),
			'list_field_groups' => array(
				'type' => 'read', 'cb' => array( $this, 'op_list_field_groups' ), 'args' => array( 'post_id', 'include_fields' ),
				'desc' => 'List ACF field groups (and optionally each group field keys/names/types).',
			),
			'yoast_set_meta' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'post_id*', 'key*', 'value*' ),
				'preview' => array( $this, 'pv_yoast_set_meta' ), 'apply' => array( $this, 'ap_yoast_set_meta' ),
				'desc' => 'Set a whitelisted Yoast SEO post meta (title, metadesc, focuskw, canonical, robots, OG/Twitter).',
			),
			'set_attachment_fields' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'alt', 'title', 'caption', 'description' ),
				'preview' => array( $this, 'pv_set_attachment_fields' ), 'apply' => array( $this, 'ap_set_attachment_fields' ),
				'desc' => 'Set alt text / title / caption / description on an existing attachment.',
			),
			'attach_to_post' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'id*', 'post_id*', 'set_as_featured' ),
				'preview' => array( $this, 'pv_attach_to_post' ), 'apply' => array( $this, 'ap_attach_to_post' ),
				'desc' => 'Set an attachment parent post, optionally also setting it as that posts featured image.',
			),
			'recount_terms' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'taxonomy', 'term_ids' ),
				'preview' => array( $this, 'pv_recount_terms' ), 'apply' => array( $this, 'ap_recount_terms' ),
				'desc' => 'Recompute cached term post-counts for a taxonomy and/or specific term_ids (not revertible; recompute is the fix).',
			),
			'delete_transient' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'key*', 'site_wide' ),
				'preview' => array( $this, 'pv_delete_transient' ), 'apply' => array( $this, 'ap_delete_transient' ),
				'desc' => 'Delete a transient to force its cached value to regenerate (cache-bust; not revertible).',
			),
			'clear_cache' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'opcache' ),
				'preview' => array( $this, 'pv_clear_cache' ), 'apply' => array( $this, 'ap_clear_cache' ),
				'desc' => 'Flush the object cache (+ detected page-cache plugins, + opcache if opcache=true). Not revertible (derived data). On a shared object cache the flush is pool-wide.',
			),

			'get_field_layouts' => array(
				'type' => 'read', 'cb' => array( $this, 'op_get_field_layouts' ), 'args' => array( 'field*', 'post_id' ),
				'desc' => 'Introspect an ACF flexible-content/repeater/group field: its layouts (modules) + each sub-field name/key/type. ACF required.',
			),
			'update_field' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'post_id*', 'selector*', 'value*' ),
				'preview' => array( $this, 'pv_update_field' ), 'apply' => array( $this, 'ap_update_field' ),
				'desc' => 'Set one ACF field value (scalar, or a whole flexible-content/repeater array of rows). String values are wp_kses_post-sanitized (rich text kept, scripts stripped). post_id accepts an id or term_X/user_X/option. Revert restores the entire prior field value. ACF required.',
			),

			'sideload_image' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'url*', 'filename', 'post_id', 'alt', 'title', 'caption', 'description', 'set_as_featured' ),
				'preview' => array( $this, 'pv_sideload_image' ), 'apply' => array( $this, 'ap_sideload_image' ),
				'desc' => 'Fetch a remote image (http/https, SSRF-validated, image MIME only) into the Media Library; optional attach + set featured. Revert deletes it.',
			),
			'upload_image_base64' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'data*', 'filename*', 'post_id', 'alt', 'title', 'caption', 'description', 'set_as_featured' ),
				'preview' => array( $this, 'pv_upload_image_base64' ), 'apply' => array( $this, 'ap_upload_image_base64' ),
				'desc' => 'Create a Media Library attachment from inline base64 image bytes (image MIME only, <=15MB decoded). Revert deletes it.',
			),

			'update_nav_menu_item' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'item_id*', 'title', 'url', 'object_id', 'parent_item_id', 'position', 'target', 'classes' ),
				'preview' => array( $this, 'pv_update_nav_menu_item' ), 'apply' => array( $this, 'ap_update_nav_menu_item' ),
				'desc' => 'Edit a menu item label/URL/target/nesting/position/classes. Revert restores the prior values.',
			),
			'remove_nav_menu_item' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'item_id*' ),
				'preview' => array( $this, 'pv_remove_nav_menu_item' ), 'apply' => array( $this, 'ap_remove_nav_menu_item' ),
				'desc' => 'Remove a single menu item. Revert re-creates it (new id). Warns if it has child items.',
			),
			'reorder_nav_menu_items' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'menu*', 'order*' ),
				'preview' => array( $this, 'pv_reorder_nav_menu_items' ), 'apply' => array( $this, 'ap_reorder_nav_menu_items' ),
				'desc' => 'Set the order of items in a menu from an explicit ordered item_id list. Revert restores prior order.',
			),
			'assign_nav_menu_location' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'location*', 'menu' ),
				'preview' => array( $this, 'pv_assign_nav_menu_location' ), 'apply' => array( $this, 'ap_assign_nav_menu_location' ),
				'desc' => 'Assign a menu to a registered theme location (or clear it with menu=0). Revert restores the prior assignment map.',
			),
			'activate_plugin' => array(
				'type' => 'write', 'tier' => 'danger', 'args' => array( 'plugin*' ),
				'preview' => array( $this, 'pv_activate_plugin' ), 'apply' => array( $this, 'ap_activate_plugin' ),
				'desc' => 'Activate an installed plugin (folder/file.php). DANGER tier (toggle + allowlist). Revert deactivates it.',
			),
			'deactivate_plugin' => array(
				'type' => 'write', 'tier' => 'danger', 'args' => array( 'plugin*', 'network' ),
				'preview' => array( $this, 'pv_deactivate_plugin' ), 'apply' => array( $this, 'ap_deactivate_plugin' ),
				'desc' => 'Deactivate an active plugin. DANGER tier (toggle + allowlist). Never deactivates JB Ops itself. Revert re-activates it.',
			),
			'set_permalink' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'post_id*', 'uri*' ),
				'preview' => array( $this, 'pv_set_permalink' ), 'apply' => array( $this, 'ap_set_permalink' ),
				'desc' => 'Set a post\'s Permalink Manager custom URI (e.g. "global-product/pu-disc").',
			),
			'flush_rewrite_rules' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array(),
				'preview' => array( $this, 'pv_flush_rewrite' ), 'apply' => array( $this, 'ap_flush_rewrite' ),
				'desc' => 'Flush WordPress rewrite rules (no diff; fixes "some URLs work, some 404/redirect").',
			),
			'revert' => array(
				'type' => 'write', 'tier' => 'core', 'args' => array( 'revert_token*' ),
				'desc' => 'Undo a previously applied write using its revert_token (single use).',
			),
		);
	}

	/* ----- read op implementations ----- */

	public function op_describe_site( $args ) {
		$plugins = get_option( 'active_plugins', array() );
		return array(
			'theme'         => array( 'stylesheet' => get_option( 'stylesheet' ), 'template' => get_option( 'template' ) ),
			'permalink'     => get_option( 'permalink_structure' ),
			'is_multisite'  => is_multisite(),
			'active_plugins'=> is_array( $plugins ) ? array_values( $plugins ) : array(),
			'paths'         => array(
				'active_theme' => 'themes/' . get_stylesheet(),
				'note'         => 'file ops accept paths relative to wp-content, e.g. "themes/' . get_stylesheet() . '/functions.php"',
			),
		);
	}

	public function op_get_post( $args ) {
		$id = isset( $args['id'] ) ? absint( $args['id'] ) : 0;
		if ( ! $id ) {
			throw new Exception( 'id is required' );
		}
		$p = get_post( $id );
		if ( ! $p ) {
			return array( 'found' => false, 'id' => $id );
		}
		return array(
			'found'       => true,
			'id'          => $p->ID,
			'title'       => $p->post_title,
			'name'        => $p->post_name,
			'type'        => $p->post_type,
			'status'      => $p->post_status,
			'parent'      => $p->post_parent,
			'permalink'   => get_permalink( $p ),
			'modified'    => $p->post_modified,
			'old_slugs'   => get_post_meta( $p->ID, '_wp_old_slug' ),
		);
	}

	public function op_query_posts( $args ) {
		$limit = isset( $args['limit'] ) ? min( 100, max( 1, absint( $args['limit'] ) ) ) : 25;
		$q = array(
			'post_type'        => isset( $args['post_type'] ) ? sanitize_key( $args['post_type'] ) : 'any',
			'post_status'      => isset( $args['post_status'] ) ? sanitize_key( $args['post_status'] ) : 'any',
			'posts_per_page'   => $limit,
			'offset'           => isset( $args['offset'] ) ? absint( $args['offset'] ) : 0,
			'orderby'          => isset( $args['orderby'] ) ? sanitize_key( $args['orderby'] ) : 'date',
			'suppress_filters' => true,
			'no_found_rows'    => true,
		);
		if ( ! empty( $args['name'] ) ) {
			$q['name'] = sanitize_title( $args['name'] );
		}
		if ( ! empty( $args['search'] ) ) {
			$q['s'] = sanitize_text_field( $args['search'] );
		}
		if ( ! empty( $args['meta_key'] ) ) {
			$q['meta_key'] = sanitize_text_field( $args['meta_key'] );
			if ( isset( $args['meta_value'] ) ) {
				$q['meta_value'] = sanitize_text_field( $args['meta_value'] );
			}
		}
		$posts = get_posts( $q );
		$out = array();
		foreach ( $posts as $p ) {
			$out[] = array(
				'id'        => $p->ID,
				'title'     => $p->post_title,
				'name'      => $p->post_name,
				'type'      => $p->post_type,
				'status'    => $p->post_status,
				'parent'    => $p->post_parent,
				'permalink' => get_permalink( $p ),
			);
		}
		return array( 'count' => count( $out ), 'posts' => $out );
	}

	public function op_get_post_meta( $args ) {
		$id = isset( $args['id'] ) ? absint( $args['id'] ) : 0;
		if ( ! $id ) {
			throw new Exception( 'id is required' );
		}
		if ( ! empty( $args['key'] ) ) {
			$key = sanitize_text_field( $args['key'] );
			return array( 'id' => $id, 'key' => $key, 'value' => $this->redact( $key, get_post_meta( $id, $key, true ) ) );
		}
		$all = get_post_meta( $id );
		$out = array();
		foreach ( (array) $all as $k => $v ) {
			$val = ( is_array( $v ) && 1 === count( $v ) ) ? $v[0] : $v;
			$out[ $k ] = $this->redact( $k, maybe_unserialize( $val ) );
		}
		return array( 'id' => $id, 'meta' => $out );
	}

	public function op_get_option( $args ) {
		$name = isset( $args['name'] ) ? sanitize_text_field( $args['name'] ) : '';
		if ( '' === $name ) {
			throw new Exception( 'name is required' );
		}
		if ( 'h_ops_settings' === $name ) {
			return array( 'name' => $name, 'value' => '[BLOCKED]' );
		}
		$value = $this->redact( $name, get_option( $name ) );
		return array( 'name' => $name, 'value' => $this->cap_size( $value ) );
	}

	public function op_list_options( $args ) {
		global $wpdb;
		$limit  = isset( $args['limit'] ) ? min( 500, max( 1, absint( $args['limit'] ) ) ) : 200;
		$search = isset( $args['search'] ) ? trim( (string) $args['search'] ) : '';
		if ( '' !== $search ) {
			$like  = '%' . $wpdb->esc_like( $search ) . '%';
			$names = $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s ORDER BY option_name LIMIT %d", $like, $limit ) );
		} else {
			$names = $wpdb->get_col( $wpdb->prepare( "SELECT option_name FROM {$wpdb->options} ORDER BY option_name LIMIT %d", $limit ) );
		}
		return array( 'count' => count( $names ), 'names' => $names );
	}

	public function op_pm_uris( $args ) {
		$uris = get_option( 'permalink-manager-uris' );
		if ( ! is_array( $uris ) ) {
			return array( 'available' => false );
		}
		$search  = isset( $args['search'] ) ? (string) $args['search'] : '';
		$post_id = isset( $args['post_id'] ) ? absint( $args['post_id'] ) : 0;
		$out = array();
		foreach ( $uris as $pid => $uri ) {
			if ( $post_id && (int) $pid !== $post_id ) {
				continue;
			}
			if ( '' !== $search && stripos( (string) $pid . ' ' . $uri, $search ) === false ) {
				continue;
			}
			$out[] = array( 'post_id' => (int) $pid, 'uri' => $uri );
		}
		return array( 'count' => count( $out ), 'uris' => array_slice( $out, 0, 500 ) );
	}

	public function op_list_redirects( $args ) {
		global $wpdb;
		$needle = isset( $args['contains'] ) ? (string) $args['contains'] : '';
		$result = array( 'rank_math' => array(), 'redirection_plugin' => array() );

		$rm = $wpdb->prefix . 'rank_math_redirections';
		if ( $wpdb->get_var( "SHOW TABLES LIKE '$rm'" ) === $rm ) {
			$rows = $wpdb->get_results( "SELECT id, sources, url_to, header_code, status FROM $rm" );
			foreach ( (array) $rows as $r ) {
				$src = maybe_unserialize( $r->sources );
				$src_str = is_array( $src ) ? wp_json_encode( $src ) : (string) $r->sources;
				if ( '' !== $needle && stripos( $src_str . ' ' . $r->url_to, $needle ) === false ) {
					continue;
				}
				$result['rank_math'][] = array( 'id' => (int) $r->id, 'code' => $r->header_code, 'status' => $r->status, 'to' => $r->url_to, 'sources' => $src );
			}
		}

		$rp = $wpdb->prefix . 'redirection_items';
		if ( $wpdb->get_var( "SHOW TABLES LIKE '$rp'" ) === $rp ) {
			$rows = $wpdb->get_results( "SELECT id, url, action_data, action_code, status, match_type FROM $rp" );
			foreach ( (array) $rows as $r ) {
				if ( '' !== $needle && stripos( $r->url . ' ' . $r->action_data, $needle ) === false ) {
					continue;
				}
				$result['redirection_plugin'][] = array( 'id' => (int) $r->id, 'code' => $r->action_code, 'status' => $r->status, 'match' => $r->match_type, 'from' => $r->url, 'to' => $r->action_data );
			}
		}
		return $result;
	}

	public function op_rewrite_rules( $args ) {
		$rules = get_option( 'rewrite_rules' );
		if ( ! is_array( $rules ) ) {
			return array( 'available' => false );
		}
		$match = isset( $args['match'] ) ? (string) $args['match'] : '';
		$out = array();
		foreach ( $rules as $regex => $query ) {
			if ( '' !== $match && stripos( $regex . ' ' . $query, $match ) === false ) {
				continue;
			}
			$out[ $regex ] = $query;
		}
		return array( 'count' => count( $out ), 'rules' => array_slice( $out, 0, 300, true ) );
	}

	public function op_resolve_url( $args ) {
		$url = isset( $args['url'] ) ? esc_url_raw( $args['url'] ) : '';
		if ( '' === $url ) {
			throw new Exception( 'url is required' );
		}
		$post_id = url_to_postid( $url );
		$out = array(
			'url'        => $url,
			'path'       => wp_parse_url( $url, PHP_URL_PATH ),
			'post_id'    => $post_id,
			'maps_to'    => $post_id ? array(
				'title'     => get_the_title( $post_id ),
				'type'      => get_post_type( $post_id ),
				'permalink' => get_permalink( $post_id ),
			) : null,
		);
		// Surface any redirect rule whose text contains this path (best effort).
		$path = trim( (string) wp_parse_url( $url, PHP_URL_PATH ), '/' );
		if ( $path ) {
			$out['matching_redirects'] = $this->op_list_redirects( array( 'contains' => $path ) );
		}
		return $out;
	}

	public function op_db_tables( $args ) {
		global $wpdb;
		$rows = $wpdb->get_results( "SHOW TABLE STATUS", ARRAY_A );
		$out = array();
		foreach ( (array) $rows as $r ) {
			$out[] = array( 'table' => $r['Name'], 'rows' => isset( $r['Rows'] ) ? (int) $r['Rows'] : null );
		}
		return array( 'count' => count( $out ), 'tables' => $out );
	}

	/* ----- user reads (read-only; auth material never returned) ----- */

	/**
	 * A single user by id / email / login / slug: safe profile fields, roles, and (by default)
	 * their user-meta. The password hash and activation key are NEVER returned; other meta
	 * values pass through the same redaction as post meta.
	 */
	public function op_get_user( $args ) {
		if ( ! empty( $args['id'] ) ) {
			$user = get_user_by( 'id', absint( $args['id'] ) );
		} elseif ( ! empty( $args['email'] ) ) {
			$user = get_user_by( 'email', sanitize_email( $args['email'] ) );
		} elseif ( ! empty( $args['login'] ) ) {
			$user = get_user_by( 'login', sanitize_user( (string) $args['login'], true ) );
		} elseif ( ! empty( $args['slug'] ) ) {
			$user = get_user_by( 'slug', sanitize_title( $args['slug'] ) );
		} else {
			throw new Exception( 'one of id, email, login or slug is required' );
		}
		if ( ! $user instanceof WP_User ) {
			return array( 'found' => false );
		}
		// Whitelist of fields only — never spread ->data, which carries user_pass / activation key.
		$out = array(
			'found'        => true,
			'id'           => (int) $user->ID,
			'login'        => $user->user_login,
			'email'        => $user->user_email,
			'slug'         => $user->user_nicename,
			'display_name' => $user->display_name,
			'registered'   => $user->user_registered,
			'roles'        => array_values( $user->roles ),
		);
		$include_meta = ! isset( $args['include_meta'] ) || ! empty( $args['include_meta'] );
		if ( $include_meta ) {
			$meta = $this->collect_user_meta( $user->ID );
			$out['meta_keys'] = count( $meta );
			$out['meta']      = $meta;
		}
		return $out;
	}

	/** User meta for one user: a single key, or all keys. Same redaction as post meta. */
	public function op_get_user_meta( $args ) {
		$id = isset( $args['user_id'] ) ? absint( $args['user_id'] ) : 0;
		if ( ! $id ) {
			throw new Exception( 'user_id is required' );
		}
		if ( ! get_user_by( 'id', $id ) ) {
			return array( 'user_id' => $id, 'found' => false );
		}
		if ( ! empty( $args['key'] ) ) {
			$key   = sanitize_text_field( $args['key'] );
			$value = $this->is_user_secret_meta( $key ) ? '[REDACTED]' : $this->redact( $key, get_user_meta( $id, $key, true ) );
			return array( 'user_id' => $id, 'found' => true, 'key' => $key, 'value' => $this->cap_size( $value ) );
		}
		return array( 'user_id' => $id, 'found' => true, 'meta' => $this->collect_user_meta( $id ) );
	}

	/**
	 * Distribution of user-meta keys across the whole usermeta table: each distinct meta_key
	 * with its row count and how many distinct users carry it. The fast way to spot a meta_key
	 * that has vanished — compare the counts to a known-good baseline. Optionally narrow to one
	 * key. Keys only (no values), so there is nothing to redact.
	 */
	public function op_usermeta_keys( $args ) {
		global $wpdb;
		$limit  = isset( $args['limit'] ) ? min( 500, max( 1, absint( $args['limit'] ) ) ) : 200;
		$table  = $wpdb->usermeta;
		$totals = $wpdb->get_row( "SELECT COUNT(*) AS rows_total, COUNT(DISTINCT user_id) AS users_with_meta, COUNT(DISTINCT meta_key) AS distinct_keys FROM $table" );
		if ( ! empty( $args['meta_key'] ) ) {
			// One key: the distinct-user count is cheap here because the WHERE filters first.
			$key = sanitize_text_field( $args['meta_key'] );
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT COUNT(*) AS cnt, COUNT(DISTINCT user_id) AS usr FROM $table WHERE meta_key = %s", $key ) );
			$keys = $row ? array( array( 'meta_key' => $key, 'rows' => (int) $row->cnt, 'users' => (int) $row->usr ) ) : array();
		} else {
			// Whole-table distribution: COUNT(*) per key only. A per-group COUNT(DISTINCT user_id)
			// forces a temp-table scan (~20s on a 450k-row table); rows == users for normal user
			// meta anyway, so it adds nothing. Use the single-key form when a distinct count matters.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT meta_key, COUNT(*) AS cnt FROM $table GROUP BY meta_key ORDER BY cnt DESC LIMIT %d", $limit ) );
			$keys = array();
			foreach ( (array) $rows as $r ) {
				$keys[] = array( 'meta_key' => $r->meta_key, 'rows' => (int) $r->cnt );
			}
		}
		return array(
			'rows_total'      => $totals ? (int) $totals->rows_total : 0,
			'users_with_meta' => $totals ? (int) $totals->users_with_meta : 0,
			'distinct_keys'   => $totals ? (int) $totals->distinct_keys : 0,
			'returned'        => count( $keys ),
			'keys'            => $keys,
		);
	}

	/** Read all of a user's meta, dropping auth material and redacting secret-shaped values. */
	private function collect_user_meta( $user_id ) {
		$all = get_user_meta( (int) $user_id );
		$out = array();
		foreach ( (array) $all as $k => $v ) {
			if ( $this->is_user_secret_meta( $k ) ) {
				$out[ $k ] = '[REDACTED]';
				continue;
			}
			$val       = ( is_array( $v ) && 1 === count( $v ) ) ? $v[0] : $v;
			$out[ $k ] = $this->redact( $k, maybe_unserialize( $val ) );
		}
		return $out;
	}

	/** Meta keys that hold auth material we never expose (redact() catches most; this is belt-and-braces). */
	private function is_user_secret_meta( $key ) {
		$k = strtolower( (string) $key );
		return ( false !== strpos( $k, 'session_tokens' )
			|| false !== strpos( $k, 'password' )
			|| 'user_activation_key' === $k );
	}

	/* ----- filesystem read ops (scoped to code dirs; read-only) ----- */

	/** Allowed roots: WP content dir (themes/plugins/mu-plugins) + core. */
	private function fs_roots() {
		$roots = array();
		foreach ( array( WP_CONTENT_DIR, ABSPATH ) as $r ) {
			$real = realpath( $r );
			if ( $real ) {
				$roots[] = $real;
			}
		}
		return array_values( array_unique( $roots ) );
	}

	private function fs_excluded_dir( $real ) {
		return (bool) preg_match( '#(/|\\\\)(\.git|node_modules|uploads|cache)(/|\\\\|$)#', $real );
	}

	private function fs_blocked_file( $real ) {
		$base = basename( $real );
		if ( preg_match( '/^\.env(\..+)?$/i', $base ) ) {
			return true;
		}
		// Config / credential files (any casing). wp-config[-*].php, dropin/secret configs,
		// server config, SSH/git/npm creds.
		if ( preg_match( '/^(wp-config([.-][^\/]*)?\.php|local-config\.php|wp-salt\.php|auth\.json|\.htpasswd|\.htaccess|\.user\.ini|php\.ini|\.npmrc|\.git-credentials|id_rsa)$/i', $base ) ) {
			return true;
		}
		if ( preg_match( '/\.(key|pem|p12|pfx|crt|sql|sqlite|db|bak|env)$/i', $base ) ) {
			return true;
		}
		return $this->fs_excluded_dir( $real );
	}

	/** Resolve a user path (absolute, or relative to wp-content) and assert it's inside an allowed root. */
	private function fs_resolve( $input, $must_be = 'any' ) {
		$input = (string) $input;
		if ( '' === $input ) {
			throw new Exception( 'path is required' );
		}
		$cand = ( '/' === $input[0] ) ? $input : rtrim( WP_CONTENT_DIR, '/' ) . '/' . ltrim( $input, '/' );
		$real = realpath( $cand );
		if ( false === $real ) {
			throw new Exception( 'path not found' );
		}
		$in = false;
		foreach ( $this->fs_roots() as $root ) {
			if ( $real === $root || strpos( $real, $root . DIRECTORY_SEPARATOR ) === 0 ) {
				$in = true;
				break;
			}
		}
		if ( ! $in ) {
			throw new Exception( 'path is outside the allowed code directories' );
		}
		if ( 'file' === $must_be && ! is_file( $real ) ) {
			throw new Exception( 'not a file' );
		}
		if ( 'dir' === $must_be && ! is_dir( $real ) ) {
			throw new Exception( 'not a directory' );
		}
		return $real;
	}

	/** Display path = relative to wp-content when possible (avoids leaking absolute server paths). */
	private function fs_rel( $real ) {
		$cd = realpath( WP_CONTENT_DIR );
		if ( $cd && strpos( $real, $cd . DIRECTORY_SEPARATOR ) === 0 ) {
			return ltrim( substr( $real, strlen( $cd ) ), '/\\' );
		}
		return $real;
	}

	private function fs_iterator( $dir ) {
		return new RecursiveIteratorIterator(
			new RecursiveCallbackFilterIterator(
				new RecursiveDirectoryIterator( $dir, FilesystemIterator::SKIP_DOTS ),
				function ( $current ) {
					return ! $this->fs_excluded_dir( $current->getPathname() );
				}
			),
			RecursiveIteratorIterator::SELF_FIRST
		);
	}

	public function op_list_files( $args ) {
		$path      = ! empty( $args['path'] ) ? $args['path'] : get_stylesheet_directory();
		$dir       = $this->fs_resolve( $path, 'dir' );
		$recursive = ! empty( $args['recursive'] );
		$ext       = ! empty( $args['ext'] ) ? ltrim( strtolower( $args['ext'] ), '.' ) : '';
		$max       = isset( $args['max'] ) ? min( 5000, max( 1, absint( $args['max'] ) ) ) : 1000;

		$out       = array();
		$truncated = false;

		$emit = function ( $real, $is_file, $size ) use ( &$out, $ext ) {
			if ( $is_file && $this->fs_blocked_file( $real ) ) {
				return;
			}
			if ( $this->fs_excluded_dir( $real ) ) {
				return;
			}
			if ( $ext && $is_file && strtolower( pathinfo( $real, PATHINFO_EXTENSION ) ) !== $ext ) {
				return;
			}
			$out[] = array( 'path' => $this->fs_rel( $real ), 'type' => $is_file ? 'file' : 'dir', 'size' => $is_file ? $size : null );
		};

		if ( $recursive ) {
			foreach ( $this->fs_iterator( $dir ) as $f ) {
				if ( count( $out ) >= $max ) {
					$truncated = true;
					break;
				}
				$emit( $f->getPathname(), $f->isFile(), $f->isFile() ? $f->getSize() : null );
			}
		} else {
			foreach ( scandir( $dir ) as $name ) {
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				if ( count( $out ) >= $max ) {
					$truncated = true;
					break;
				}
				$real = $dir . DIRECTORY_SEPARATOR . $name;
				$emit( $real, is_file( $real ), is_file( $real ) ? filesize( $real ) : null );
			}
		}
		return array( 'dir' => $this->fs_rel( $dir ), 'count' => count( $out ), 'truncated' => $truncated, 'entries' => $out );
	}

	public function op_read_file( $args ) {
		$file = $this->fs_resolve( $args['path'] ?? '', 'file' );
		if ( $this->fs_blocked_file( $file ) ) {
			throw new Exception( 'this file is blocked from reading' );
		}
		if ( filesize( $file ) > 2 * 1024 * 1024 ) {
			throw new Exception( 'file too large to read (> 2MB)' );
		}
		$content = file_get_contents( $file );
		if ( strpos( substr( $content, 0, 8000 ), "\0" ) !== false ) {
			throw new Exception( 'binary file' );
		}
		$all_lines = explode( "\n", $content );
		$total     = count( $all_lines );
		$start     = isset( $args['start_line'] ) ? max( 1, absint( $args['start_line'] ) ) : 1;
		$count     = isset( $args['lines'] ) ? min( 2000, max( 1, absint( $args['lines'] ) ) ) : min( 2000, $total );
		$slice     = array_slice( $all_lines, $start - 1, $count );
		$text      = implode( "\n", $slice );
		if ( strlen( $text ) > 300000 ) {
			$text = substr( $text, 0, 300000 ) . "\n…[truncated]";
		}
		return array(
			'path'        => $this->fs_rel( $file ),
			'total_lines' => $total,
			'start_line'  => $start,
			'returned'    => count( $slice ),
			'content'     => $text,
		);
	}

	public function op_search_files( $args ) {
		$pattern = isset( $args['pattern'] ) ? (string) $args['pattern'] : '';
		if ( '' === $pattern ) {
			throw new Exception( 'pattern is required' );
		}
		$is_regex = ! empty( $args['regex'] );
		$rx       = '';
		if ( $is_regex ) {
			$rx = '#' . str_replace( '#', '\\#', $pattern ) . '#i';
			if ( false === @preg_match( $rx, '' ) ) {
				throw new Exception( 'invalid regex' );
			}
		}
		$path = ! empty( $args['path'] ) ? $args['path'] : get_stylesheet_directory();
		$dir  = $this->fs_resolve( $path, 'dir' );
		$ext  = ! empty( $args['ext'] ) ? ltrim( strtolower( $args['ext'] ), '.' ) : 'php';
		$max  = isset( $args['max_matches'] ) ? min( 1000, max( 1, absint( $args['max_matches'] ) ) ) : 200;

		$matches       = array();
		$files_scanned = 0;
		$truncated     = false;

		foreach ( $this->fs_iterator( $dir ) as $f ) {
			if ( ! $f->isFile() || $this->fs_blocked_file( $f->getPathname() ) ) {
				continue;
			}
			if ( $ext && strtolower( $f->getExtension() ) !== $ext ) {
				continue;
			}
			if ( $f->getSize() > 1500000 ) {
				continue;
			}
			if ( $files_scanned >= 8000 ) {
				$truncated = true;
				break;
			}
			$files_scanned++;
			$fp = fopen( $f->getPathname(), 'r' );
			if ( ! $fp ) {
				continue;
			}
			$ln = 0;
			while ( ( $line = fgets( $fp ) ) !== false ) {
				$ln++;
				$hit = $is_regex ? preg_match( $rx, $line ) : ( stripos( $line, $pattern ) !== false );
				if ( $hit ) {
					$matches[] = array( 'file' => $this->fs_rel( $f->getPathname() ), 'line' => $ln, 'text' => trim( substr( $line, 0, 300 ) ) );
					if ( count( $matches ) >= $max ) {
						$truncated = true;
						fclose( $fp );
						break 2;
					}
				}
			}
			fclose( $fp );
		}
		return array( 'pattern' => $pattern, 'regex' => $is_regex, 'root' => $this->fs_rel( $dir ), 'files_scanned' => $files_scanned, 'count' => count( $matches ), 'truncated' => $truncated, 'matches' => $matches );
	}

	/* ----- filesystem write op (danger-tier; scoped to wp-content) ----- */

	/** Lexically resolve . and .. in a path WITHOUT touching the filesystem (works for not-yet-existing files). */
	private function fs_norm_abs( $input ) {
		$input = (string) $input;
		if ( '' === $input ) {
			throw new Exception( 'path is required' );
		}
		$cand  = ( '/' === $input[0] ) ? $input : rtrim( WP_CONTENT_DIR, '/' ) . '/' . ltrim( $input, '/' );
		$cand  = str_replace( '\\', '/', $cand );
		$stack = array();
		foreach ( explode( '/', $cand ) as $seg ) {
			if ( '' === $seg || '.' === $seg ) {
				continue;
			}
			if ( '..' === $seg ) {
				array_pop( $stack );
				continue;
			}
			$stack[] = $seg;
		}
		return '/' . implode( '/', $stack );
	}

	/**
	 * Is $path at or under $root? Compared case-INSENSITIVELY so structural checks
	 * (scope + self-exclusion) hold on case-insensitive volumes (APFS/NTFS/shared hosts),
	 * where realpath() preserves the caller's casing. Over-blocks at worst on a
	 * case-sensitive FS — never under-blocks.
	 */
	private function path_under( $path, $root ) {
		$p = strtolower( rtrim( (string) $path, '/\\' ) );
		$r = strtolower( rtrim( (string) $root, '/\\' ) );
		return '' !== $r && ( $p === $r || 0 === strpos( $p, $r . '/' ) );
	}

	/**
	 * Resolve a writable target path: scoped to wp-content, symlink-safe, with the
	 * non-negotiable blocklist (secrets/config, excluded dirs, JB Ops own dir) applied.
	 * Works for files that do not exist yet. Returns target/parent/existed/need_dirs/rel.
	 */
	private function fs_resolve_write( $input, $create_dirs ) {
		$target = $this->fs_norm_abs( $input );
		$wc     = realpath( WP_CONTENT_DIR );
		if ( ! $wc ) {
			throw new Exception( 'wp-content directory not found' );
		}
		// Walk up to the deepest existing ancestor, then realpath it (resolves symlinks).
		$probe = $target;
		$tail  = array();
		while ( $probe && '/' !== $probe && ! file_exists( $probe ) ) {
			array_unshift( $tail, basename( $probe ) );
			$probe = dirname( $probe );
		}
		$anchor = realpath( $probe );
		if ( false === $anchor ) {
			throw new Exception( 'cannot resolve target location' );
		}
		if ( ! $this->path_under( $anchor, $wc ) ) {
			throw new Exception( 'path is outside wp-content' );
		}
		$real = $tail ? $anchor . '/' . implode( '/', $tail ) : $anchor;
		// Writes are scoped to themes/ and plugins/ ONLY — never the wp-content root,
		// mu-plugins (auto-loaded), uploads, languages, or dropins like
		// object-cache.php / advanced-cache.php / db.php (auto-executed, survive deactivation).
		if ( ! $this->path_under( $real, $wc . DIRECTORY_SEPARATOR . 'themes' )
			&& ! $this->path_under( $real, $wc . DIRECTORY_SEPARATOR . 'plugins' ) ) {
			throw new Exception( 'file writes are scoped to wp-content/themes and wp-content/plugins' );
		}
		// Never let the bridge rewrite its own code (and thus its own gates). Compared
		// case-insensitively: on APFS/NTFS/most shared hosts realpath() preserves the
		// REQUESTED casing, so a case-sensitive compare here is bypassable (e.g. H-OPS/).
		$self = realpath( plugin_dir_path( __FILE__ ) );
		if ( $self && $this->path_under( $real, $self ) ) {
			throw new Exception( 'refusing to write inside the JB Ops plugin directory' );
		}
		if ( is_dir( $real ) ) {
			throw new Exception( 'path is a directory, not a file' );
		}
		// Hard blocks (kept even with "no type limit"): secrets/config + .git/uploads/cache.
		if ( $this->fs_blocked_file( $real ) ) {
			throw new Exception( 'this path is blocked from writing (secret/config file or excluded dir)' );
		}
		$parent = dirname( $real );
		return array(
			'target'    => $real,
			'parent'    => $parent,
			'existed'   => is_file( $real ),
			'need_dirs' => ! is_dir( $parent ),
			'rel'       => $this->fs_rel( $real ),
		);
	}

	/** Decode the write payload: prefer content_base64 (binary-safe) over content. Returns [bytes, is_base64]. */
	private function write_file_content( $args ) {
		if ( isset( $args['content_base64'] ) && '' !== $args['content_base64'] ) {
			$raw = base64_decode( (string) $args['content_base64'], true );
			if ( false === $raw ) {
				throw new Exception( 'content_base64 is not valid base64' );
			}
			return array( $raw, true );
		}
		return array( (string) ( $args['content'] ?? '' ), false );
	}

	/** Compact, non-huge view of file content for the diff (full content lives only in the revert payload). */
	private function file_view( $s ) {
		if ( null === $s ) {
			return null;
		}
		return array( 'bytes' => strlen( $s ), 'sha1' => sha1( $s ), 'preview' => strlen( $s ) > 2000 ? substr( $s, 0, 2000 ) : $s );
	}

	public function pv_write_file( $args ) {
		$create_dirs = $this->truthy( $args['create_dirs'] ?? false );
		$overwrite   = array_key_exists( 'overwrite', $args ) ? $this->truthy( $args['overwrite'] ) : true;
		$res         = $this->fs_resolve_write( $args['path'] ?? '', $create_dirs );
		if ( $res['existed'] && ! $overwrite ) {
			throw new Exception( 'file exists and overwrite is false' );
		}
		if ( $res['need_dirs'] && ! $create_dirs ) {
			throw new Exception( 'parent directory does not exist (pass create_dirs:true to create it)' );
		}
		list( $content, $is_b64 ) = $this->write_file_content( $args );
		if ( strlen( $content ) > self::MAX_WRITE_BYTES ) {
			throw new Exception( sprintf( 'content exceeds the max write size of %d bytes', self::MAX_WRITE_BYTES ) );
		}
		$before = $res['existed'] ? (string) file_get_contents( $res['target'] ) : null;
		$would  = ! $res['existed'] || ( $before !== $content );
		return array(
			'before'       => $this->file_view( $before ),
			'after'        => $this->file_view( $content ),
			'would_change' => $would,
			'summary'      => sprintf( '%s file %s (%d bytes%s)', $res['existed'] ? 'replace' : 'create', $res['rel'], strlen( $content ), $is_b64 ? ', from base64' : '' ),
			'revert'       => array( 'type' => 'file', 'path' => $res['target'], 'rel' => $res['rel'], 'existed' => $res['existed'], 'before' => $before ),
			'_io'          => array( 'target' => $res['target'], 'parent' => $res['parent'], 'need_dirs' => $res['need_dirs'], 'content' => $content ),
		);
	}

	public function ap_write_file( $args, $preview = array() ) {
		$io = isset( $preview['_io'] ) && is_array( $preview['_io'] ) ? $preview['_io'] : null;
		if ( null === $io ) {
			$preview = $this->pv_write_file( $args ); // defensive recompute
			$io      = $preview['_io'];
		}
		if ( ! empty( $io['need_dirs'] ) && ! wp_mkdir_p( $io['parent'] ) ) {
			throw new Exception( 'failed to create parent directories (check permissions)' );
		}
		$bytes = file_put_contents( $io['target'], $io['content'], LOCK_EX );
		if ( false === $bytes ) {
			throw new Exception( 'failed to write file (check filesystem permissions)' );
		}
		if ( function_exists( 'opcache_invalidate' ) ) {
			@opcache_invalidate( $io['target'], true ); // so a re-written .php takes effect immediately
		}
		return array(
			'path'    => $this->fs_rel( $io['target'] ),
			'bytes'   => $bytes,
			'created' => empty( $preview['revert']['existed'] ),
		);
	}

	/* ----- DB export op (danger-tier + export toggle; pure-PHP gzipped SQL dump) ----- */

	/**
	 * Protected directory the dumps are written to (uploads/jb-ops-exports). Hardened with an
	 * Apache deny + an index stub. The real guard is the 160-bit random filename plus the
	 * bearer-gated download route — the file is never linked anywhere and is short-lived.
	 */
	private function export_dir() {
		$up  = wp_upload_dir();
		$dir = trailingslashit( $up['basedir'] ) . 'jb-ops-exports';
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		$ht = $dir . '/.htaccess';
		if ( ! file_exists( $ht ) ) {
			@file_put_contents( $ht, "# JB Ops DB exports — no direct web access.\nRequire all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n" );
		}
		$idx = $dir . '/index.php';
		if ( ! file_exists( $idx ) ) {
			@file_put_contents( $idx, "<?php // Silence is golden.\n" );
		}
		return $dir;
	}

	/** Delete dumps + manifests whose TTL has passed (best-effort housekeeping, runs on every export). */
	private function export_prune( $dir ) {
		foreach ( (array) glob( $dir . '/*.json' ) as $mf ) {
			$m = json_decode( (string) @file_get_contents( $mf ), true );
			if ( ! is_array( $m ) || (int) ( $m['expires'] ?? 0 ) < time() ) {
				$base = preg_replace( '/\.json$/', '', $mf );
				@unlink( $base . '.sql.gz' );
				@unlink( $mf );
			}
		}
	}

	/** Resolve which tables to dump: explicit list -> all -> (default) this install's prefix. */
	private function export_collect_tables( $args ) {
		global $wpdb;
		$all = $wpdb->get_col( 'SHOW TABLES' );
		$all = is_array( $all ) ? $all : array();
		if ( ! empty( $args['tables'] ) ) {
			$want = is_array( $args['tables'] ) ? $args['tables'] : preg_split( '/[\s,]+/', (string) $args['tables'] );
			$want = array_filter( array_map( 'trim', (array) $want ) );
			return array_values( array_intersect( $all, $want ) );
		}
		if ( $this->truthy( $args['all_tables'] ?? false ) ) {
			return $all;
		}
		$base = $wpdb->base_prefix; // matches single-site + every blog table on multisite
		$sel  = array();
		foreach ( $all as $t ) {
			if ( 0 === strpos( $t, $base ) ) {
				$sel[] = $t;
			}
		}
		return $sel ? $sel : $all;
	}

	/** Approximate size/row totals from SHOW TABLE STATUS (no full scan). */
	private function export_estimate( $tables ) {
		global $wpdb;
		$rows = 0;
		$bytes = 0;
		foreach ( $tables as $t ) {
			$st = $wpdb->get_row( $wpdb->prepare( 'SHOW TABLE STATUS LIKE %s', $t ) );
			if ( $st ) {
				$rows  += (int) $st->Rows;
				$bytes += (int) $st->Data_length + (int) $st->Index_length;
			}
		}
		return array( 'tables' => count( $tables ), 'approx_rows' => $rows, 'approx_bytes' => $bytes );
	}

	/**
	 * Serialize-safe recursive search/replace: rewrites $from -> $to inside plain strings AND
	 * inside PHP-serialized blobs (widgets, ACF, options) so string-length prefixes stay correct.
	 * Mirrors the well-known recursive_unserialize_replace approach.
	 */
	private function sr_replace( $data, $from, $to ) {
		if ( '' === (string) $from ) {
			return $data;
		}
		try {
			if ( is_string( $data ) && is_serialized( $data ) ) {
				$un = @unserialize( $data ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
				if ( false !== $un || 'b:0;' === $data ) {
					return serialize( $this->sr_replace( $un, $from, $to ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
				}
			}
			if ( is_array( $data ) ) {
				$out = array();
				foreach ( $data as $k => $v ) {
					$out[ $k ] = $this->sr_replace( $v, $from, $to );
				}
				return $out;
			}
			if ( is_object( $data ) ) {
				// Only generic stdClass is round-trippable here; recurse its public props.
				if ( $data instanceof \__PHP_Incomplete_Class ) {
					return $data;
				}
				$obj = clone $data;
				foreach ( get_object_vars( $obj ) as $k => $v ) {
					$obj->$k = $this->sr_replace( $v, $from, $to );
				}
				return $obj;
			}
			if ( is_string( $data ) ) {
				return str_replace( $from, $to, $data );
			}
		} catch ( \Throwable $e ) {
			return $data; // never let one bad blob abort the whole dump
		}
		return $data;
	}

	/** Stream one table to the gz handle: DROP + CREATE, then batched INSERTs. */
	private function dump_table( $gz, $table, $from, $to ) {
		global $wpdb;
		$bt = '`' . str_replace( '`', '``', $table ) . '`';
		gzwrite( $gz, "\nDROP TABLE IF EXISTS $bt;\n" );
		$create = $wpdb->get_row( "SHOW CREATE TABLE $bt", ARRAY_N );
		if ( $create && isset( $create[1] ) ) {
			gzwrite( $gz, $create[1] . ";\n\n" );
		}
		$do_sr  = ( '' !== (string) $from );
		$batch  = self::EXPORT_BATCH;
		$offset = 0;
		while ( true ) {
			// Table name is from SHOW TABLES (trusted) and backtick-escaped; limit/offset are ints.
			$rows = $wpdb->get_results( "SELECT * FROM $bt LIMIT $batch OFFSET $offset", ARRAY_N );
			if ( empty( $rows ) ) {
				break;
			}
			$tuples = array();
			foreach ( $rows as $row ) {
				$cells = array();
				foreach ( $row as $val ) {
					if ( null === $val ) {
						$cells[] = 'NULL';
						continue;
					}
					if ( $do_sr ) {
						$val = $this->sr_replace( $val, $from, $to );
					}
					$cells[] = "'" . $wpdb->_real_escape( (string) $val ) . "'";
				}
				$tuples[] = '(' . implode( ',', $cells ) . ')';
			}
			gzwrite( $gz, "INSERT INTO $bt VALUES " . implode( ",\n", $tuples ) . ";\n" );
			$offset += $batch;
			if ( count( $rows ) < $batch ) {
				break;
			}
		}
	}

	public function pv_export_db( $args ) {
		$tables = $this->export_collect_tables( $args );
		if ( empty( $tables ) ) {
			throw new Exception( 'no tables matched for export (check the tables/all_tables args)' );
		}
		if ( ! function_exists( 'gzopen' ) ) {
			throw new Exception( 'zlib (gzopen) is unavailable on this host; cannot produce a gzipped dump' );
		}
		$est  = $this->export_estimate( $tables );
		$from = isset( $args['search'] ) ? (string) $args['search'] : '';
		$to   = isset( $args['replace'] ) ? (string) $args['replace'] : '';
		return array(
			'before'       => null,
			'after'        => array(
				'tables'           => $est['tables'],
				'approx_rows'      => $est['approx_rows'],
				'approx_bytes'     => $est['approx_bytes'],
				'gzipped'          => true,
				'search_replace'   => ( '' !== $from ) ? array( 'from' => $from, 'to' => $to ) : null,
				'includes_secrets' => true,
			),
			'would_change' => true,
			'summary'      => sprintf(
				'export %d table(s) (~%s, ~%d rows) to a gzipped SQL dump%s — includes secrets/PII, no redaction',
				$est['tables'],
				size_format( max( 1, $est['approx_bytes'] ) ),
				$est['approx_rows'],
				( '' !== $from ) ? sprintf( '; serialize-safe replace "%s" => "%s"', $from, $to ) : ''
			),
			// Real revert (delete the dump) is built at apply time, once we know the file path.
			'revert'       => null,
		);
	}

	public function ap_export_db( $args, $preview = array() ) {
		if ( ! function_exists( 'gzopen' ) ) {
			throw new Exception( 'zlib (gzopen) is unavailable on this host; cannot produce a gzipped dump' );
		}
		@set_time_limit( 0 );
		$tables = $this->export_collect_tables( $args );
		if ( empty( $tables ) ) {
			throw new Exception( 'no tables matched for export' );
		}
		$from = isset( $args['search'] ) ? (string) $args['search'] : '';
		$to   = isset( $args['replace'] ) ? (string) $args['replace'] : '';

		$dir = $this->export_dir();
		$this->export_prune( $dir );

		$token = bin2hex( random_bytes( 20 ) ); // 40 hex chars / 160 bits
		$fname = $token . '.sql.gz';
		$path  = $dir . '/' . $fname;
		$meta_path = $dir . '/' . $token . '.json';

		$gz = gzopen( $path, 'wb6' );
		if ( ! $gz ) {
			throw new Exception( 'could not open the export file for writing (check uploads permissions)' );
		}
		global $wpdb;
		$charset = ( defined( 'DB_CHARSET' ) && DB_CHARSET ) ? DB_CHARSET : 'utf8mb4';
		gzwrite( $gz, "-- JB Ops Bridge DB export\n-- site: " . home_url() . "\n-- generated: " . current_time( 'mysql' ) . "\n" );
		if ( '' !== $from ) {
			gzwrite( $gz, '-- serialize-safe search-replace: ' . $from . ' => ' . $to . "\n" );
		}
		gzwrite( $gz, "/*!40101 SET NAMES " . $charset . " */;\nSET FOREIGN_KEY_CHECKS=0;\nSET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\nSET autocommit=0;\nSTART TRANSACTION;\n" );
		foreach ( $tables as $t ) {
			$this->dump_table( $gz, $t, $from, $to );
		}
		gzwrite( $gz, "\nCOMMIT;\nSET FOREIGN_KEY_CHECKS=1;\n" );
		gzclose( $gz );

		$bytes   = (int) filesize( $path );
		$sha     = hash_file( 'sha256', $path );
		$expires = time() + self::EXPORT_TTL;
		@file_put_contents( $meta_path, wp_json_encode( array(
			'file'    => $fname,
			'bytes'   => $bytes,
			'sha256'  => $sha,
			'expires' => $expires,
			'tables'  => count( $tables ),
			'created' => current_time( 'mysql' ),
			'site'    => home_url(),
		) ), LOCK_EX );

		return array(
			'download_token' => $token,
			'download_url'   => rest_url( H_OPS_NS . '/export/' . $token ),
			'download_path'  => '/wp-json/' . H_OPS_NS . '/export/' . $token,
			'bytes'          => $bytes,
			'gzipped'        => true,
			'sha256'         => $sha,
			'tables'         => count( $tables ),
			'expires_in'     => self::EXPORT_TTL,
			'search_replace' => ( '' !== $from ) ? array( 'from' => $from, 'to' => $to ) : null,
			'note'           => 'GET this with your bearer token (curl -OJ -H "Authorization: Bearer <TOKEN>" <download_url>). One-time; expires in 1h; deletes on first download.',
			'_revert'        => array( 'type' => 'export_file', 'path' => $path, 'meta' => $meta_path ),
		);
	}

	/**
	 * Stream a generated export, then delete it (single use). Bearer auth already passed via the
	 * route's permission_callback; here we validate the token, enforce the TTL, and confine the
	 * served path to the export dir.
	 */
	public function handle_export_download( WP_REST_Request $request ) {
		$token = preg_replace( '/[^a-f0-9]/', '', (string) $request['token'] );
		if ( strlen( $token ) < 32 ) {
			return $this->fail( 'export_download', 'bad_token', 'Invalid download token.', 400 );
		}
		$dir = $this->export_dir();
		$this->export_prune( $dir );
		$meta_path = $dir . '/' . $token . '.json';
		if ( ! is_file( $meta_path ) ) {
			return $this->fail( 'export_download', 'not_found', 'Export not found, already downloaded, or expired.', 404 );
		}
		$m = json_decode( (string) file_get_contents( $meta_path ), true );
		if ( ! is_array( $m ) || (int) ( $m['expires'] ?? 0 ) < time() ) {
			@unlink( $meta_path );
			@unlink( $dir . '/' . $token . '.sql.gz' );
			return $this->fail( 'export_download', 'expired', 'Export expired.', 410 );
		}
		$file = $dir . '/' . basename( (string) $m['file'] );
		$rp   = realpath( $file );
		if ( ! $rp || ! $this->path_under( $rp, realpath( $dir ) ) || ! is_file( $rp ) ) {
			return $this->fail( 'export_download', 'gone', 'Export file is missing.', 410 );
		}

		$this->audit( 'export_db', array( 'token' => substr( $token, 0, 8 ) . '…' ), 'downloaded', array( 'bytes' => (int) $m['bytes'] ) );

		nocache_headers();
		status_header( 200 );
		header( 'Content-Type: application/gzip' );
		header( 'Content-Disposition: attachment; filename="' . basename( $rp ) . '"' );
		header( 'Content-Length: ' . filesize( $rp ) );
		header( 'X-Content-Type-Options: nosniff' );
		$fp = fopen( $rp, 'rb' );
		if ( $fp ) {
			while ( ! feof( $fp ) ) {
				echo fread( $fp, 1048576 ); // phpcs:ignore WordPress.Security.EscapeOutput
			}
			fclose( $fp );
		}
		// Single use: drop the dump + manifest the moment it has been served.
		@unlink( $rp );
		@unlink( $meta_path );
		exit;
	}

	/* ----- write op implementations: pv_* = preview (no persist), ap_* = apply ----- */

	private function require_post( $args ) {
		$id = isset( $args['id'] ) ? absint( $args['id'] ) : 0;
		if ( ! $id || ! get_post( $id ) ) {
			throw new Exception( 'valid id is required' );
		}
		return $id;
	}

	/** True when WP trash is functional; with EMPTY_TRASH_DAYS===0 a "trash" is a permanent delete. */
	private function trash_enabled() {
		return ! ( defined( 'EMPTY_TRASH_DAYS' ) && 0 === (int) EMPTY_TRASH_DAYS );
	}
	/** Posts the bridge must never trash (front page / posts page). */
	private function is_protected_post( $id ) {
		$id = (int) $id;
		if ( ! $id ) {
			return false;
		}
		$front = (int) get_option( 'page_on_front' );
		$blog  = (int) get_option( 'page_for_posts' );
		return ( $front && $id === $front ) || ( $blog && $id === $blog );
	}
	/** Interpret a JSON-ish boolean argument (true / "true" / 1 / "1" / "yes" / "on"). */
	private function truthy( $v ) {
		if ( is_bool( $v ) ) {
			return $v;
		}
		return in_array( strtolower( (string) $v ), array( '1', 'true', 'yes', 'on' ), true );
	}

	public function pv_update_post_meta( $args ) {
		$id = $this->require_post( $args );
		if ( empty( $args['key'] ) ) {
			throw new Exception( 'key is required' );
		}
		$key    = sanitize_text_field( $args['key'] );
		if ( $this->blocked_meta_key( $key ) ) {
			throw new Exception( 'meta key "' . $key . '" is blocked from writes' );
		}
		$value  = $args['value'] ?? null;
		$before = get_post_meta( $id, $key, true );
		$existed = metadata_exists( 'post', $id, $key );
		return array(
			'before'       => $this->redact( $key, $before ),
			'after'        => $this->redact( $key, $value ),
			'would_change' => $before !== $value,
			'summary'      => sprintf( 'post %d meta "%s"', $id, $key ),
			'revert'       => array( 'type' => 'meta', 'id' => $id, 'key' => $key, 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_update_post_meta( $args ) {
		$key = sanitize_text_field( $args['key'] );
		if ( $this->blocked_meta_key( $key ) ) {
			throw new Exception( 'meta key is blocked from writes' );
		}
		update_post_meta( absint( $args['id'] ), $key, $args['value'] ?? null );
		return true;
	}

	public function pv_delete_post_meta( $args ) {
		$id = $this->require_post( $args );
		if ( empty( $args['key'] ) ) {
			throw new Exception( 'key is required' );
		}
		$key     = sanitize_text_field( $args['key'] );
		$before  = get_post_meta( $id, $key, true );
		$existed = metadata_exists( 'post', $id, $key );
		return array(
			'before'       => $this->redact( $key, $before ),
			'after'        => null,
			'would_change' => $existed,
			'summary'      => sprintf( 'delete post %d meta "%s"', $id, $key ),
			'revert'       => array( 'type' => 'meta', 'id' => $id, 'key' => $key, 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_delete_post_meta( $args ) {
		delete_post_meta( absint( $args['id'] ), sanitize_text_field( $args['key'] ) );
		return true;
	}

	/** Options whose change could break or hijack the site — never writable via the API. Prefix/pattern-aware. */
	private function blocked_option( $name ) {
		global $wpdb;
		$name  = (string) $name;
		$exact = array(
			'h_ops_settings', 'siteurl', 'home', 'active_plugins', 'active_sitewide_plugins',
			'template', 'stylesheet', 'admin_email', 'new_admin_email', 'users_can_register',
			'default_role', 'sticky_posts', 'nav_menu_locations', 'cron', 'rewrite_rules',
			'user_roles', $wpdb->prefix . 'user_roles', 'mailserver_pass', 'auth_key',
		);
		if ( in_array( $name, $exact, true ) ) {
			return true;
		}
		foreach ( array( 'h_ops_', 'widget_', 'theme_mods_', '_transient_', '_site_transient_' ) as $prefix ) {
			if ( 0 === strpos( $name, $prefix ) ) {
				return true;
			}
		}
		// Role/capability/credential-style option names.
		return (bool) preg_match( '/(capabilities|user_roles|user_level)$/i', $name );
	}

	/** Meta keys that must never be written via the API (privilege/credential vectors). */
	private function blocked_meta_key( $key ) {
		global $wpdb;
		$key   = (string) $key;
		$exact = array( 'session_tokens', $wpdb->prefix . 'capabilities', $wpdb->prefix . 'user_level', '_application_passwords' );
		if ( in_array( $key, $exact, true ) ) {
			return true;
		}
		return (bool) preg_match( '/(capabilities|user_level|session_tokens|application_passwords)$/i', $key );
	}
	public function pv_update_option( $args ) {
		$name = isset( $args['name'] ) ? sanitize_text_field( $args['name'] ) : '';
		if ( '' === $name ) {
			throw new Exception( 'name is required' );
		}
		if ( $this->blocked_option( $name ) ) {
			throw new Exception( 'option "' . $name . '" is blocked from writes' );
		}
		$before  = get_option( $name, null );
		$existed = ( null !== $before ) || ( false !== get_option( $name, false ) );
		$value   = $args['value'] ?? null;
		return array(
			'before'       => $this->cap_size( $this->redact( $name, $before ) ),
			'after'        => $this->cap_size( $this->redact( $name, $value ) ),
			'would_change' => $before !== $value,
			'summary'      => sprintf( 'option "%s"', $name ),
			'revert'       => array( 'type' => 'option', 'name' => $name, 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_update_option( $args ) {
		$name = sanitize_text_field( $args['name'] );
		if ( $this->blocked_option( $name ) ) {
			throw new Exception( 'blocked option' );
		}
		update_option( $name, $args['value'] ?? null );
		return true;
	}

	private $post_field_whitelist = array( 'post_status', 'post_name', 'post_parent', 'post_title', 'post_excerpt', 'post_content' );
	public function pv_update_post_field( $args ) {
		$id    = $this->require_post( $args );
		$field = isset( $args['field'] ) ? sanitize_key( $args['field'] ) : '';
		if ( ! in_array( $field, $this->post_field_whitelist, true ) ) {
			throw new Exception( 'field must be one of: ' . implode( ', ', $this->post_field_whitelist ) );
		}
		$post   = get_post( $id );
		$before = $post->$field;
		$value  = $args['value'] ?? '';
		return array(
			'before'       => $before,
			'after'        => $value,
			'would_change' => (string) $before !== (string) $value,
			'summary'      => sprintf( 'post %d %s', $id, $field ),
			'revert'       => array( 'type' => 'post_field', 'id' => $id, 'field' => $field, 'value' => $before ),
		);
	}
	public function ap_update_post_field( $args ) {
		$id    = absint( $args['id'] );
		$field = sanitize_key( $args['field'] );
		if ( ! in_array( $field, $this->post_field_whitelist, true ) ) {
			throw new Exception( 'field not allowed' );
		}
		$res = wp_update_post( array( 'ID' => $id, $field => $args['value'] ?? '' ), true );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	/** Statuses an AI is allowed to create a post in. */
	private $create_status_whitelist = array( 'draft', 'pending', 'private', 'publish', 'future' );
	public function pv_create_post( $args ) {
		$title = isset( $args['post_title'] ) ? (string) $args['post_title'] : '';
		if ( '' === trim( $title ) ) {
			throw new Exception( 'post_title is required' );
		}
		$type = isset( $args['post_type'] ) ? sanitize_key( $args['post_type'] ) : 'post';
		if ( ! post_type_exists( $type ) ) {
			throw new Exception( 'post_type "' . $type . '" does not exist' );
		}
		$status = isset( $args['post_status'] ) ? sanitize_key( $args['post_status'] ) : 'draft';
		if ( ! in_array( $status, $this->create_status_whitelist, true ) ) {
			throw new Exception( 'post_status must be one of: ' . implode( ', ', $this->create_status_whitelist ) );
		}
		$parent = isset( $args['post_parent'] ) ? absint( $args['post_parent'] ) : 0;
		if ( $parent && ! get_post( $parent ) ) {
			throw new Exception( 'post_parent ' . $parent . ' does not exist' );
		}
		$after = array(
			'post_type'    => $type,
			'post_status'  => $status,
			'post_title'   => $title,
			'post_content' => isset( $args['post_content'] ) ? (string) $args['post_content'] : '',
			'post_excerpt' => isset( $args['post_excerpt'] ) ? (string) $args['post_excerpt'] : '',
			'post_name'    => isset( $args['post_name'] ) ? sanitize_title( $args['post_name'] ) : '',
			'post_parent'  => $parent,
			'post_author'  => isset( $args['post_author'] ) ? absint( $args['post_author'] ) : 0,
		);
		return array(
			'before'       => null,
			'after'        => $after,
			'would_change' => true,
			'summary'      => sprintf( 'create %s "%s" (%s)', $type, $title, $status ),
			'revert'       => null, // the new post id isn't known until apply; ap_create_post returns the real revert payload
		);
	}
	public function ap_create_post( $args, $preview ) {
		$after   = $preview['after'];
		$postarr = array(
			'post_type'    => $after['post_type'],
			'post_status'  => $after['post_status'],
			'post_title'   => $after['post_title'],
			'post_content' => $after['post_content'],
			'post_excerpt' => $after['post_excerpt'],
			'post_parent'  => $after['post_parent'],
			'post_author'  => $after['post_author'],
		);
		if ( '' !== $after['post_name'] ) {
			$postarr['post_name'] = $after['post_name'];
		}
		$id = wp_insert_post( $postarr, true );
		if ( is_wp_error( $id ) ) {
			throw new Exception( $id->get_error_message() );
		}
		return array(
			'created'   => true,
			'id'        => (int) $id,
			'permalink' => get_permalink( $id ),
			'_revert'   => array( 'type' => 'post_create', 'id' => (int) $id ),
		);
	}

	private $unpublish_targets = array( 'draft', 'pending', 'private' );

	public function pv_trash_post( $args ) {
		$id = $this->require_post( $args );
		if ( ! $this->trash_enabled() ) {
			throw new Exception( 'Trash is disabled on this site (EMPTY_TRASH_DAYS=0); trashing would permanently delete. Refusing.' );
		}
		if ( $this->is_protected_post( $id ) ) {
			throw new Exception( 'Refusing to trash the front page / posts page.' );
		}
		$post = get_post( $id );
		if ( 'trash' === $post->post_status ) {
			return array( 'before' => 'trash', 'after' => 'trash', 'would_change' => false, 'summary' => sprintf( 'post %d already trashed', $id ), 'revert' => null );
		}
		return array(
			'before'       => $post->post_status,
			'after'        => 'trash',
			'would_change' => true,
			'summary'      => sprintf( 'trash post %d ("%s")', $id, $post->post_title ),
			'revert'       => array( 'type' => 'post_trash', 'id' => $id, 'status' => $post->post_status ),
		);
	}
	public function ap_trash_post( $args ) {
		$id = absint( $args['id'] );
		if ( ! $this->trash_enabled() ) {
			throw new Exception( 'trash disabled' );
		}
		if ( $this->is_protected_post( $id ) ) {
			throw new Exception( 'protected post' );
		}
		if ( ! wp_trash_post( $id ) ) {
			throw new Exception( 'wp_trash_post failed' );
		}
		return true;
	}

	public function pv_untrash_post( $args ) {
		$id   = $this->require_post( $args );
		$post = get_post( $id );
		if ( 'trash' !== $post->post_status ) {
			throw new Exception( 'post is not in the trash' );
		}
		$prev = get_post_meta( $id, '_wp_trash_meta_status', true );
		return array(
			'before'       => 'trash',
			'after'        => $prev ? $prev : 'draft',
			'would_change' => true,
			'summary'      => sprintf( 'restore post %d from trash', $id ),
			'revert'       => array( 'type' => 'post_untrash', 'id' => $id, 'prev_status' => $prev ),
		);
	}
	public function ap_untrash_post( $args ) {
		$id   = absint( $args['id'] );
		$prev = get_post_meta( $id, '_wp_trash_meta_status', true );
		if ( ! wp_untrash_post( $id ) ) {
			throw new Exception( 'wp_untrash_post failed' );
		}
		// WP 5.6+ untrashes to 'draft'; explicitly restore the captured pre-trash status.
		if ( $prev && get_post_status( $id ) !== $prev ) {
			$res = wp_update_post( array( 'ID' => $id, 'post_status' => $prev ), true );
			if ( is_wp_error( $res ) ) {
				throw new Exception( $res->get_error_message() );
			}
		}
		return true;
	}

	public function pv_publish_post( $args ) {
		$id     = $this->require_post( $args );
		$post   = get_post( $id );
		$before = $post->post_status;
		if ( 'publish' === $before ) {
			return array( 'before' => 'publish', 'after' => 'publish', 'would_change' => false, 'summary' => sprintf( 'post %d already published', $id ), 'revert' => null );
		}
		if ( 'trash' === $before ) {
			throw new Exception( 'post is in the trash; untrash it first' );
		}
		return array(
			'before'       => $before,
			'after'        => 'publish',
			'would_change' => true,
			'summary'      => sprintf( 'publish post %d (was %s) - note: publishing fires notifications/feeds a status revert cannot un-send', $id, $before ),
			'revert'       => array( 'type' => 'post_field', 'id' => $id, 'field' => 'post_status', 'value' => $before ),
		);
	}
	public function ap_publish_post( $args ) {
		$id  = absint( $args['id'] );
		$res = wp_update_post( array( 'ID' => $id, 'post_status' => 'publish' ), true );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	public function pv_unpublish_post( $args ) {
		$id     = $this->require_post( $args );
		$post   = get_post( $id );
		$before = $post->post_status;
		$to     = isset( $args['to_status'] ) ? sanitize_key( $args['to_status'] ) : 'draft';
		if ( ! in_array( $to, $this->unpublish_targets, true ) ) {
			throw new Exception( 'to_status must be one of: ' . implode( ', ', $this->unpublish_targets ) );
		}
		return array(
			'before'       => $before,
			'after'        => $to,
			'would_change' => (string) $before !== (string) $to,
			'summary'      => sprintf( 'set post %d status %s -> %s', $id, $before, $to ),
			'revert'       => array( 'type' => 'post_field', 'id' => $id, 'field' => 'post_status', 'value' => $before ),
		);
	}
	public function ap_unpublish_post( $args ) {
		$id = absint( $args['id'] );
		$to = isset( $args['to_status'] ) ? sanitize_key( $args['to_status'] ) : 'draft';
		if ( ! in_array( $to, $this->unpublish_targets, true ) ) {
			throw new Exception( 'invalid to_status' );
		}
		$res = wp_update_post( array( 'ID' => $id, 'post_status' => $to ), true );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	public function pv_set_featured_image( $args ) {
		$id  = $this->require_post( $args );
		$att = isset( $args['attachment_id'] ) ? absint( $args['attachment_id'] ) : -1;
		if ( $att < 0 ) {
			throw new Exception( 'attachment_id is required (0 to clear)' );
		}
		if ( $att > 0 && ( 'attachment' !== get_post_type( $att ) || ! wp_attachment_is_image( $att ) ) ) {
			throw new Exception( 'attachment_id must be an image attachment' );
		}
		$before  = get_post_meta( $id, '_thumbnail_id', true );
		$existed = metadata_exists( 'post', $id, '_thumbnail_id' );
		return array(
			'before'       => $before ? $before : null,
			'after'        => $att ? $att : null,
			'would_change' => (string) $before !== (string) $att,
			'summary'      => $att ? sprintf( 'set featured image of post %d to attachment %d', $id, $att ) : sprintf( 'clear featured image of post %d', $id ),
			'revert'       => array( 'type' => 'meta', 'id' => $id, 'key' => '_thumbnail_id', 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_set_featured_image( $args ) {
		$id  = absint( $args['id'] );
		$att = absint( $args['attachment_id'] );
		if ( $att > 0 ) {
			if ( 'attachment' !== get_post_type( $att ) || ! wp_attachment_is_image( $att ) ) {
				throw new Exception( 'not an image attachment' );
			}
			if ( ! set_post_thumbnail( $id, $att ) ) {
				throw new Exception( 'failed to set featured image (attachment has no usable thumbnail size)' );
			}
		} else {
			delete_post_thumbnail( $id );
		}
		return true;
	}

	public function pv_set_page_template( $args ) {
		$id  = $this->require_post( $args );
		$tpl = isset( $args['template'] ) ? (string) $args['template'] : '';
		if ( '' === $tpl ) {
			throw new Exception( 'template is required ("default" to reset)' );
		}
		if ( 'default' !== $tpl ) {
			$templates = wp_get_theme()->get_page_templates( get_post( $id ) );
			if ( ! isset( $templates[ $tpl ] ) ) {
				throw new Exception( 'template "' . $tpl . '" is not registered for this post type/theme' );
			}
		}
		$before  = get_post_meta( $id, '_wp_page_template', true );
		$existed = metadata_exists( 'post', $id, '_wp_page_template' );
		return array(
			'before'       => $before ? $before : null,
			'after'        => $tpl,
			'would_change' => (string) $before !== (string) $tpl,
			'summary'      => sprintf( 'set page template of post %d to %s', $id, $tpl ),
			'revert'       => array( 'type' => 'meta', 'id' => $id, 'key' => '_wp_page_template', 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_set_page_template( $args ) {
		$id  = absint( $args['id'] );
		$tpl = (string) $args['template'];
		update_post_meta( $id, '_wp_page_template', $tpl );
		return true;
	}

	public function pv_set_post_format( $args ) {
		$id    = $this->require_post( $args );
		$fmt   = isset( $args['format'] ) ? sanitize_key( $args['format'] ) : '';
		$valid = array_values( array_unique( array_merge( array( 'standard' ), get_post_format_slugs() ) ) );
		if ( '' === $fmt || ! in_array( $fmt, $valid, true ) ) {
			throw new Exception( 'format must be one of: ' . implode( ', ', $valid ) );
		}
		$before = get_post_format( $id );
		if ( false === $before ) {
			$before = 'standard';
		}
		return array(
			'before'       => $before,
			'after'        => $fmt,
			'would_change' => $before !== $fmt,
			'summary'      => sprintf( 'set post %d format to %s', $id, $fmt ),
			'revert'       => array( 'type' => 'post_format', 'id' => $id, 'value' => $before ),
		);
	}
	public function ap_set_post_format( $args ) {
		$id  = absint( $args['id'] );
		$fmt = sanitize_key( $args['format'] );
		$res = set_post_format( $id, 'standard' === $fmt ? false : $fmt );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	public function pv_set_sticky( $args ) {
		$id   = $this->require_post( $args );
		$want = $this->truthy( isset( $args['sticky'] ) ? $args['sticky'] : null );
		$is   = is_sticky( $id );
		return array(
			'before'       => $is,
			'after'        => $want,
			'would_change' => $is !== $want,
			'summary'      => sprintf( '%s post %d', $want ? 'stick' : 'unstick', $id ),
			'revert'       => array( 'type' => 'sticky', 'id' => $id, 'was_sticky' => $is ),
		);
	}
	public function ap_set_sticky( $args ) {
		$id   = absint( $args['id'] );
		$want = $this->truthy( isset( $args['sticky'] ) ? $args['sticky'] : null );
		if ( $want ) {
			stick_post( $id );
		} else {
			unstick_post( $id );
		}
		return true;
	}

	public function pv_set_menu_order( $args ) {
		$id = $this->require_post( $args );
		if ( ! isset( $args['menu_order'] ) ) {
			throw new Exception( 'menu_order is required' );
		}
		$val    = (int) $args['menu_order'];
		$before = (int) get_post( $id )->menu_order;
		return array(
			'before'       => $before,
			'after'        => $val,
			'would_change' => $before !== $val,
			'summary'      => sprintf( 'set post %d menu_order %d -> %d', $id, $before, $val ),
			'revert'       => array( 'type' => 'post_field', 'id' => $id, 'field' => 'menu_order', 'value' => $before ),
		);
	}
	public function ap_set_menu_order( $args ) {
		$id  = absint( $args['id'] );
		$val = (int) $args['menu_order'];
		$res = wp_update_post( array( 'ID' => $id, 'menu_order' => $val ), true );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	/** Validate/normalize a list of term_ids for a taxonomy. Rejects non-integers (string values would mint new terms). */
	private function normalize_term_ids( $raw, $tax ) {
		if ( ! is_array( $raw ) ) {
			$raw = array( $raw );
		}
		$ids = array();
		foreach ( $raw as $v ) {
			if ( ! is_int( $v ) && ( ! is_scalar( $v ) || is_bool( $v ) || ! ctype_digit( (string) $v ) ) ) {
				throw new Exception( 'terms must be integer term_ids (create terms first; string values would mint new terms)' );
			}
			$tid = absint( $v );
			$t   = get_term( $tid, $tax );
			if ( ! $t || is_wp_error( $t ) ) {
				throw new Exception( 'term ' . $tid . ' not found in taxonomy ' . $tax );
			}
			$ids[] = $tid;
		}
		return array_values( array_unique( $ids ) );
	}

	public function op_get_term( $args ) {
		$id  = isset( $args['term_id'] ) ? absint( $args['term_id'] ) : 0;
		if ( ! $id ) {
			throw new Exception( 'term_id is required' );
		}
		$tax  = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		$term = $tax ? get_term( $id, $tax ) : get_term( $id );
		if ( ! $term || is_wp_error( $term ) ) {
			return array( 'found' => false, 'term_id' => $id );
		}
		return array(
			'found'            => true,
			'term_id'          => (int) $term->term_id,
			'name'             => $term->name,
			'slug'             => $term->slug,
			'taxonomy'         => $term->taxonomy,
			'parent'           => (int) $term->parent,
			'count'            => (int) $term->count,
			'description'      => $term->description,
			'term_taxonomy_id' => (int) $term->term_taxonomy_id,
		);
	}
	public function op_list_terms( $args ) {
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		if ( '' === $tax || ! taxonomy_exists( $tax ) ) {
			throw new Exception( 'valid taxonomy is required' );
		}
		$limit = isset( $args['limit'] ) ? min( 200, max( 1, absint( $args['limit'] ) ) ) : 100;
		$q = array(
			'taxonomy'   => $tax,
			'hide_empty' => ! empty( $args['hide_empty'] ),
			'number'     => $limit,
			'offset'     => isset( $args['offset'] ) ? absint( $args['offset'] ) : 0,
			'orderby'    => isset( $args['orderby'] ) ? sanitize_key( $args['orderby'] ) : 'name',
		);
		if ( isset( $args['search'] ) && '' !== $args['search'] ) {
			$q['search'] = sanitize_text_field( $args['search'] );
		}
		if ( isset( $args['parent'] ) ) {
			$q['parent'] = absint( $args['parent'] );
		}
		if ( ! empty( $args['include'] ) ) {
			$q['include'] = array_map( 'absint', (array) $args['include'] );
		}
		if ( ! empty( $args['exclude'] ) ) {
			$q['exclude'] = array_map( 'absint', (array) $args['exclude'] );
		}
		$terms = get_terms( $q );
		if ( is_wp_error( $terms ) ) {
			throw new Exception( $terms->get_error_message() );
		}
		$out = array();
		foreach ( $terms as $t ) {
			$out[] = array( 'term_id' => (int) $t->term_id, 'name' => $t->name, 'slug' => $t->slug, 'parent' => (int) $t->parent, 'count' => (int) $t->count );
		}
		return array( 'taxonomy' => $tax, 'count' => count( $out ), 'terms' => $out );
	}
	public function op_get_object_terms( $args ) {
		$oid = isset( $args['object_id'] ) ? absint( $args['object_id'] ) : 0;
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		if ( ! $oid ) {
			throw new Exception( 'object_id is required' );
		}
		if ( '' === $tax || ! taxonomy_exists( $tax ) ) {
			throw new Exception( 'valid taxonomy is required' );
		}
		$terms = wp_get_object_terms( $oid, $tax );
		if ( is_wp_error( $terms ) ) {
			throw new Exception( $terms->get_error_message() );
		}
		$out = array();
		foreach ( $terms as $t ) {
			$out[] = array( 'term_id' => (int) $t->term_id, 'name' => $t->name, 'slug' => $t->slug );
		}
		return array( 'object_id' => $oid, 'taxonomy' => $tax, 'count' => count( $out ), 'terms' => $out );
	}
	public function op_get_term_meta( $args ) {
		$id = isset( $args['term_id'] ) ? absint( $args['term_id'] ) : 0;
		if ( ! $id ) {
			throw new Exception( 'term_id is required' );
		}
		if ( ! empty( $args['key'] ) ) {
			$k = sanitize_text_field( $args['key'] );
			return array( 'term_id' => $id, 'key' => $k, 'value' => $this->redact( $k, get_term_meta( $id, $k, true ) ) );
		}
		$all = get_term_meta( $id );
		$out = array();
		foreach ( (array) $all as $k => $v ) {
			$val = ( is_array( $v ) && 1 === count( $v ) ) ? $v[0] : $v;
			$out[ $k ] = $this->redact( $k, maybe_unserialize( $val ) );
		}
		return array( 'term_id' => $id, 'meta' => $out );
	}
	public function op_list_taxonomies( $args ) {
		$ot    = isset( $args['object_type'] ) ? sanitize_key( $args['object_type'] ) : '';
		$taxes = $ot ? get_object_taxonomies( $ot, 'objects' ) : get_taxonomies( array(), 'objects' );
		$pub   = ! empty( $args['public_only'] );
		$out   = array();
		foreach ( $taxes as $t ) {
			if ( $pub && empty( $t->public ) ) {
				continue;
			}
			$out[] = array(
				'name'         => $t->name,
				'label'        => $t->label,
				'hierarchical' => (bool) $t->hierarchical,
				'public'       => (bool) $t->public,
				'show_ui'      => (bool) $t->show_ui,
				'object_type'  => array_values( (array) $t->object_type ),
			);
		}
		return array( 'count' => count( $out ), 'taxonomies' => $out );
	}

	public function pv_create_term( $args ) {
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		if ( '' === $tax || ! taxonomy_exists( $tax ) ) {
			throw new Exception( 'valid taxonomy is required' );
		}
		$name = isset( $args['name'] ) ? (string) $args['name'] : '';
		if ( '' === trim( $name ) ) {
			throw new Exception( 'name is required' );
		}
		$parent = isset( $args['parent'] ) ? absint( $args['parent'] ) : 0;
		if ( $parent ) {
			if ( ! is_taxonomy_hierarchical( $tax ) ) {
				throw new Exception( 'taxonomy is not hierarchical; parent not allowed' );
			}
			$pt = get_term( $parent, $tax );
			if ( ! $pt || is_wp_error( $pt ) ) {
				throw new Exception( 'parent term does not exist in this taxonomy' );
			}
		}
		return array(
			'before'       => null,
			'after'        => array( 'taxonomy' => $tax, 'name' => $name, 'slug' => isset( $args['slug'] ) ? sanitize_title( $args['slug'] ) : '', 'parent' => $parent, 'description' => isset( $args['description'] ) ? (string) $args['description'] : '' ),
			'would_change' => true,
			'summary'      => sprintf( 'create term "%s" in %s', $name, $tax ),
			'revert'       => null,
		);
	}
	public function ap_create_term( $args, $preview ) {
		$a   = $preview['after'];
		$res = wp_insert_term( $a['name'], $a['taxonomy'], array( 'slug' => $a['slug'], 'parent' => $a['parent'], 'description' => $a['description'] ) );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		$tid = (int) $res['term_id'];
		return array( 'created' => true, 'term_id' => $tid, 'taxonomy' => $a['taxonomy'], '_revert' => array( 'type' => 'term_create', 'term_id' => $tid, 'taxonomy' => $a['taxonomy'] ) );
	}

	public function pv_update_term( $args ) {
		$id  = isset( $args['term_id'] ) ? absint( $args['term_id'] ) : 0;
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		if ( ! $id ) {
			throw new Exception( 'term_id is required' );
		}
		if ( '' === $tax || ! taxonomy_exists( $tax ) ) {
			throw new Exception( 'valid taxonomy is required' );
		}
		$term = get_term( $id, $tax );
		if ( ! $term || is_wp_error( $term ) ) {
			throw new Exception( 'term not found in this taxonomy' );
		}
		$upd = array();
		$changed = array();
		if ( isset( $args['name'] ) && '' !== trim( (string) $args['name'] ) ) {
			$upd['name'] = (string) $args['name'];
			$changed[]   = 'name';
		}
		if ( isset( $args['description'] ) ) {
			$upd['description'] = (string) $args['description'];
			$changed[]          = 'description';
		}
		if ( isset( $args['parent'] ) ) {
			$parent = absint( $args['parent'] );
			if ( $parent ) {
				if ( ! is_taxonomy_hierarchical( $tax ) ) {
					throw new Exception( 'taxonomy is not hierarchical' );
				}
				if ( $parent === $id ) {
					throw new Exception( 'a term cannot be its own parent' );
				}
				if ( in_array( $id, array_map( 'intval', get_ancestors( $parent, $tax, 'taxonomy' ) ), true ) ) {
					throw new Exception( 'cycle: parent is a descendant of this term' );
				}
				$pt = get_term( $parent, $tax );
				if ( ! $pt || is_wp_error( $pt ) ) {
					throw new Exception( 'parent term does not exist' );
				}
			}
			$upd['parent'] = $parent;
			$changed[]     = 'parent';
		}
		if ( empty( $upd ) ) {
			throw new Exception( 'nothing to update (provide name, description and/or parent)' );
		}
		return array(
			'before'       => array( 'name' => $term->name, 'description' => $term->description, 'parent' => (int) $term->parent ),
			'after'        => $upd,
			'would_change' => ( isset( $upd['name'] ) && $upd['name'] !== $term->name ) || ( isset( $upd['description'] ) && $upd['description'] !== $term->description ) || ( isset( $upd['parent'] ) && (int) $upd['parent'] !== (int) $term->parent ),
			'summary'      => sprintf( 'update term %d (%s) [%s]', $id, $tax, implode( ',', $changed ) ),
			'revert'       => array( 'type' => 'term_update', 'term_id' => $id, 'taxonomy' => $tax, 'name' => $term->name, 'description' => $term->description, 'parent' => (int) $term->parent ),
		);
	}
	public function ap_update_term( $args ) {
		$id  = absint( $args['term_id'] );
		$tax = sanitize_key( $args['taxonomy'] );
		$upd = array();
		if ( isset( $args['name'] ) && '' !== trim( (string) $args['name'] ) ) {
			$upd['name'] = (string) $args['name'];
		}
		if ( isset( $args['description'] ) ) {
			$upd['description'] = (string) $args['description'];
		}
		if ( isset( $args['parent'] ) ) {
			$upd['parent'] = absint( $args['parent'] );
		}
		$res = wp_update_term( $id, $tax, $upd );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	public function pv_set_term_parent( $args ) {
		$id  = isset( $args['term_id'] ) ? absint( $args['term_id'] ) : 0;
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		if ( ! $id ) {
			throw new Exception( 'term_id is required' );
		}
		if ( '' === $tax || ! taxonomy_exists( $tax ) ) {
			throw new Exception( 'valid taxonomy is required' );
		}
		if ( ! is_taxonomy_hierarchical( $tax ) ) {
			throw new Exception( 'taxonomy is not hierarchical' );
		}
		$term = get_term( $id, $tax );
		if ( ! $term || is_wp_error( $term ) ) {
			throw new Exception( 'term not found' );
		}
		if ( ! isset( $args['parent'] ) ) {
			throw new Exception( 'parent is required (0 for top-level)' );
		}
		$parent = absint( $args['parent'] );
		if ( $parent ) {
			if ( $parent === $id ) {
				throw new Exception( 'a term cannot be its own parent' );
			}
			if ( in_array( $id, array_map( 'intval', get_ancestors( $parent, $tax, 'taxonomy' ) ), true ) ) {
				throw new Exception( 'cycle: parent is a descendant' );
			}
			$pt = get_term( $parent, $tax );
			if ( ! $pt || is_wp_error( $pt ) ) {
				throw new Exception( 'parent term does not exist' );
			}
		}
		return array(
			'before'       => (int) $term->parent,
			'after'        => $parent,
			'would_change' => (int) $term->parent !== $parent,
			'summary'      => sprintf( 'set term %d (%s) parent -> %d', $id, $tax, $parent ),
			'revert'       => array( 'type' => 'term_update', 'term_id' => $id, 'taxonomy' => $tax, 'name' => $term->name, 'description' => $term->description, 'parent' => (int) $term->parent ),
		);
	}
	public function ap_set_term_parent( $args ) {
		$id     = absint( $args['term_id'] );
		$tax    = sanitize_key( $args['taxonomy'] );
		$parent = absint( $args['parent'] );
		$res    = wp_update_term( $id, $tax, array( 'parent' => $parent ) );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	public function pv_set_post_terms( $args ) {
		$oid = isset( $args['object_id'] ) ? absint( $args['object_id'] ) : 0;
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		if ( ! $oid || ! get_post( $oid ) ) {
			throw new Exception( 'valid object_id (post) is required' );
		}
		if ( '' === $tax || ! taxonomy_exists( $tax ) ) {
			throw new Exception( 'valid taxonomy is required' );
		}
		if ( ! is_object_in_taxonomy( get_post( $oid )->post_type, $tax ) ) {
			throw new Exception( 'taxonomy "' . $tax . '" is not registered for this post type' );
		}
		if ( ! isset( $args['terms'] ) ) {
			throw new Exception( 'terms is required (array of term_ids)' );
		}
		$terms  = $this->normalize_term_ids( $args['terms'], $tax );
		$append = ! empty( $args['append'] );
		$before = wp_get_object_terms( $oid, $tax, array( 'fields' => 'ids' ) );
		if ( is_wp_error( $before ) ) {
			$before = array();
		}
		$before = array_map( 'intval', $before );
		return array(
			'before'       => $before,
			'after'        => $append ? array_values( array_unique( array_merge( $before, $terms ) ) ) : $terms,
			'would_change' => true,
			'summary'      => sprintf( '%s %d terms on post %d (%s)', $append ? 'append' : 'set', count( $terms ), $oid, $tax ),
			'revert'       => array( 'type' => 'term_relationship', 'object_id' => $oid, 'taxonomy' => $tax, 'terms' => $before ),
		);
	}
	public function ap_set_post_terms( $args ) {
		$oid    = absint( $args['object_id'] );
		$tax    = sanitize_key( $args['taxonomy'] );
		$terms  = $this->normalize_term_ids( $args['terms'], $tax );
		$append = ! empty( $args['append'] );
		$res    = wp_set_object_terms( $oid, $terms, $tax, $append );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	public function pv_remove_post_terms( $args ) {
		$oid = isset( $args['object_id'] ) ? absint( $args['object_id'] ) : 0;
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		if ( ! $oid || ! get_post( $oid ) ) {
			throw new Exception( 'valid object_id (post) is required' );
		}
		if ( '' === $tax || ! taxonomy_exists( $tax ) ) {
			throw new Exception( 'valid taxonomy is required' );
		}
		if ( ! is_object_in_taxonomy( get_post( $oid )->post_type, $tax ) ) {
			throw new Exception( 'taxonomy "' . $tax . '" is not registered for this post type' );
		}
		if ( ! isset( $args['terms'] ) ) {
			throw new Exception( 'terms is required (array of term_ids)' );
		}
		$remove = $this->normalize_term_ids( $args['terms'], $tax );
		$before = wp_get_object_terms( $oid, $tax, array( 'fields' => 'ids' ) );
		if ( is_wp_error( $before ) ) {
			$before = array();
		}
		$before = array_map( 'intval', $before );
		$after  = array_values( array_diff( $before, $remove ) );
		return array(
			'before'       => $before,
			'after'        => $after,
			'would_change' => $before !== $after,
			'summary'      => sprintf( 'remove %d terms from post %d (%s)', count( $remove ), $oid, $tax ),
			'revert'       => array( 'type' => 'term_relationship', 'object_id' => $oid, 'taxonomy' => $tax, 'terms' => $before ),
		);
	}
	public function ap_remove_post_terms( $args ) {
		$oid    = absint( $args['object_id'] );
		$tax    = sanitize_key( $args['taxonomy'] );
		$remove = $this->normalize_term_ids( $args['terms'], $tax );
		$res    = wp_remove_object_terms( $oid, $remove, $tax );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	/** Discussion options this op may set, with their value type. */
	private $discussion_opts = array( 'default_comment_status' => 'onoff', 'default_ping_status' => 'onoff', 'comment_registration' => 'bool', 'comment_moderation' => 'bool', 'comment_previously_approved' => 'bool', 'close_comments_for_old_posts' => 'bool', 'comments_per_page' => 'int', 'close_comments_days_old' => 'int' );

	public function op_get_theme_mods( $args ) {
		$theme = isset( $args['theme'] ) ? sanitize_text_field( $args['theme'] ) : '';
		$mods  = $theme ? get_option( 'theme_mods_' . $theme ) : get_theme_mods();
		if ( ! is_array( $mods ) ) {
			$mods = array();
		}
		$out = array();
		foreach ( $mods as $k => $v ) {
			$out[ $k ] = $this->cap_size( $this->redact( (string) $k, $v ) );
		}
		return array( 'theme' => $theme ? $theme : get_stylesheet(), 'mods' => $out );
	}
	public function op_get_settings_overview( $args ) {
		$front = (int) get_option( 'page_on_front' );
		$blog  = (int) get_option( 'page_for_posts' );
		return array(
			'general'    => array(
				'blogname'        => get_option( 'blogname' ),
				'blogdescription' => get_option( 'blogdescription' ),
				'timezone_string' => get_option( 'timezone_string' ),
				'gmt_offset'      => get_option( 'gmt_offset' ),
				'date_format'     => get_option( 'date_format' ),
				'time_format'     => get_option( 'time_format' ),
				'start_of_week'   => (int) get_option( 'start_of_week' ),
			),
			'reading'    => array(
				'show_on_front'       => get_option( 'show_on_front' ),
				'page_on_front'       => $front,
				'page_on_front_title' => $front ? get_the_title( $front ) : null,
				'page_for_posts'      => $blog,
				'page_for_posts_title'=> $blog ? get_the_title( $blog ) : null,
				'posts_per_page'      => (int) get_option( 'posts_per_page' ),
				'blog_public'         => (int) get_option( 'blog_public' ),
			),
			'discussion' => array(
				'default_comment_status' => get_option( 'default_comment_status' ),
				'default_ping_status'    => get_option( 'default_ping_status' ),
				'comment_moderation'     => (int) get_option( 'comment_moderation' ),
				'comment_registration'   => (int) get_option( 'comment_registration' ),
			),
		);
	}

	public function pv_set_site_identity( $args ) {
		$items = array();
		$sum   = array();
		if ( isset( $args['title'] ) ) {
			$items['blogname'] = sanitize_text_field( $args['title'] );
			$sum[] = 'title';
		}
		if ( isset( $args['tagline'] ) ) {
			$items['blogdescription'] = sanitize_text_field( $args['tagline'] );
			$sum[] = 'tagline';
		}
		if ( empty( $items ) ) {
			throw new Exception( 'provide title and/or tagline' );
		}
		return array(
			'before'       => array( 'blogname' => get_option( 'blogname' ), 'blogdescription' => get_option( 'blogdescription' ) ),
			'after'        => $items,
			'would_change' => $this->options_would_change( $items ),
			'summary'      => 'site identity: ' . implode( ', ', $sum ),
			'revert'       => array( 'type' => 'options_set', 'items' => $this->snapshot_options( array_keys( $items ) ) ),
		);
	}
	public function ap_set_site_identity( $args ) {
		if ( isset( $args['title'] ) ) {
			update_option( 'blogname', sanitize_text_field( $args['title'] ) );
		}
		if ( isset( $args['tagline'] ) ) {
			update_option( 'blogdescription', sanitize_text_field( $args['tagline'] ) );
		}
		return true;
	}

	public function pv_set_site_logo( $args ) {
		if ( ! current_theme_supports( 'custom-logo' ) ) {
			throw new Exception( 'the active theme does not support a custom logo' );
		}
		$att = isset( $args['attachment_id'] ) ? absint( $args['attachment_id'] ) : -1;
		if ( $att < 0 ) {
			throw new Exception( 'attachment_id is required (0 to clear)' );
		}
		if ( $att > 0 && ( 'attachment' !== get_post_type( $att ) || ! wp_attachment_is_image( $att ) ) ) {
			throw new Exception( 'attachment_id must be an image attachment' );
		}
		$theme  = get_stylesheet();
		$before = get_theme_mod( 'custom_logo' );
		return array(
			'before'       => $before ? (int) $before : null,
			'after'        => $att ? $att : null,
			'would_change' => (int) $before !== $att,
			'summary'      => $att ? sprintf( 'set custom logo to attachment %d', $att ) : 'clear custom logo',
			'revert'       => $this->theme_mod_revert( $theme, 'custom_logo' ),
		);
	}
	public function ap_set_site_logo( $args ) {
		$att = absint( $args['attachment_id'] );
		if ( $att > 0 ) {
			if ( 'attachment' !== get_post_type( $att ) || ! wp_attachment_is_image( $att ) ) {
				throw new Exception( 'not an image attachment' );
			}
			set_theme_mod( 'custom_logo', $att );
		} else {
			remove_theme_mod( 'custom_logo' );
		}
		return true;
	}

	public function pv_set_site_icon( $args ) {
		$att = isset( $args['attachment_id'] ) ? absint( $args['attachment_id'] ) : -1;
		if ( $att < 0 ) {
			throw new Exception( 'attachment_id is required (0 to clear)' );
		}
		if ( $att > 0 && ( 'attachment' !== get_post_type( $att ) || ! wp_attachment_is_image( $att ) ) ) {
			throw new Exception( 'attachment_id must be an image attachment' );
		}
		$before  = get_option( 'site_icon' );
		$existed = ( false !== get_option( 'site_icon', false ) );
		return array(
			'before'       => $before ? (int) $before : null,
			'after'        => $att ? $att : null,
			'would_change' => (int) $before !== $att,
			'summary'      => $att ? sprintf( 'set site icon to attachment %d', $att ) : 'clear site icon',
			'revert'       => array( 'type' => 'option', 'name' => 'site_icon', 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_set_site_icon( $args ) {
		$att = absint( $args['attachment_id'] );
		if ( $att > 0 ) {
			if ( 'attachment' !== get_post_type( $att ) || ! wp_attachment_is_image( $att ) ) {
				throw new Exception( 'not an image attachment' );
			}
			update_option( 'site_icon', $att );
		} else {
			delete_option( 'site_icon' );
		}
		return true;
	}

	public function pv_update_theme_mod( $args ) {
		$key = isset( $args['key'] ) ? sanitize_key( $args['key'] ) : '';
		if ( '' === $key ) {
			throw new Exception( 'key is required' );
		}
		if ( ! array_key_exists( 'value', $args ) ) {
			throw new Exception( 'value is required' );
		}
		$theme   = $this->resolve_theme( $args );
		$mods    = get_option( 'theme_mods_' . $theme );
		if ( ! is_array( $mods ) ) {
			$mods = array();
		}
		$existed = array_key_exists( $key, $mods );
		$before  = $existed ? $mods[ $key ] : null;
		return array(
			'before'       => $this->cap_size( $this->redact( $key, $before ) ),
			'after'        => $this->cap_size( $this->redact( $key, $args['value'] ) ),
			'would_change' => true,
			'summary'      => sprintf( 'theme mod "%s" on %s', $key, $theme ),
			'revert'       => array( 'type' => 'theme_mod', 'theme' => $theme, 'key' => $key, 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_update_theme_mod( $args ) {
		$key   = sanitize_key( $args['key'] );
		$theme = $this->resolve_theme( $args );
		$opt   = 'theme_mods_' . $theme;
		$mods  = get_option( $opt );
		if ( ! is_array( $mods ) ) {
			$mods = array();
		}
		$mods[ $key ] = $args['value'];
		update_option( $opt, $mods );
		return true;
	}

	public function pv_delete_theme_mod( $args ) {
		$key = isset( $args['key'] ) ? sanitize_key( $args['key'] ) : '';
		if ( '' === $key ) {
			throw new Exception( 'key is required' );
		}
		$theme   = $this->resolve_theme( $args );
		$mods    = get_option( 'theme_mods_' . $theme );
		if ( ! is_array( $mods ) ) {
			$mods = array();
		}
		$existed = array_key_exists( $key, $mods );
		$before  = $existed ? $mods[ $key ] : null;
		return array(
			'before'       => $this->cap_size( $this->redact( $key, $before ) ),
			'after'        => null,
			'would_change' => $existed,
			'summary'      => sprintf( 'delete theme mod "%s" on %s', $key, $theme ),
			'revert'       => array( 'type' => 'theme_mod', 'theme' => $theme, 'key' => $key, 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_delete_theme_mod( $args ) {
		$key   = sanitize_key( $args['key'] );
		$theme = $this->resolve_theme( $args );
		$opt   = 'theme_mods_' . $theme;
		$mods  = get_option( $opt );
		if ( ! is_array( $mods ) ) {
			$mods = array();
		}
		unset( $mods[ $key ] );
		update_option( $opt, $mods );
		return true;
	}

	public function pv_set_timezone( $args ) {
		$tz  = isset( $args['timezone_string'] ) ? sanitize_text_field( $args['timezone_string'] ) : '';
		$off = isset( $args['gmt_offset'] ) ? $args['gmt_offset'] : null;
		if ( null !== $off && ( ! is_scalar( $off ) || ! is_numeric( $off ) ) ) {
			throw new Exception( 'gmt_offset must be a number' );
		}
		if ( '' === $tz && null === $off ) {
			throw new Exception( 'provide timezone_string (IANA) or gmt_offset' );
		}
		if ( '' !== $tz && ! in_array( $tz, timezone_identifiers_list(), true ) ) {
			throw new Exception( 'invalid IANA timezone_string' );
		}
		if ( '' !== $tz ) {
			$items = array( 'timezone_string' => $tz, 'gmt_offset' => '' );
		} else {
			$items = array( 'gmt_offset' => (string) floatval( $off ), 'timezone_string' => '' );
		}
		return array(
			'before'       => array( 'timezone_string' => get_option( 'timezone_string' ), 'gmt_offset' => get_option( 'gmt_offset' ) ),
			'after'        => $items,
			'would_change' => $this->options_would_change( $items ),
			'summary'      => 'site timezone',
			'revert'       => array( 'type' => 'options_set', 'items' => $this->snapshot_options( array( 'timezone_string', 'gmt_offset' ) ) ),
		);
	}
	public function ap_set_timezone( $args ) {
		$tz  = isset( $args['timezone_string'] ) ? sanitize_text_field( $args['timezone_string'] ) : '';
		$off = isset( $args['gmt_offset'] ) ? $args['gmt_offset'] : null;
		if ( null !== $off && ( ! is_scalar( $off ) || ! is_numeric( $off ) ) ) {
			throw new Exception( 'gmt_offset must be a number' );
		}
		if ( '' !== $tz ) {
			if ( ! in_array( $tz, timezone_identifiers_list(), true ) ) {
				throw new Exception( 'invalid IANA timezone_string' );
			}
			update_option( 'timezone_string', $tz );
			update_option( 'gmt_offset', '' );
		} elseif ( null !== $off ) {
			update_option( 'gmt_offset', (string) floatval( $off ) );
			update_option( 'timezone_string', '' );
		} else {
			throw new Exception( 'nothing to set' );
		}
		return true;
	}

	public function pv_set_date_time_format( $args ) {
		$items = array();
		if ( isset( $args['date_format'] ) ) {
			$items['date_format'] = sanitize_text_field( $args['date_format'] );
		}
		if ( isset( $args['time_format'] ) ) {
			$items['time_format'] = sanitize_text_field( $args['time_format'] );
		}
		if ( isset( $args['start_of_week'] ) ) {
			$sow = absint( $args['start_of_week'] );
			if ( $sow > 6 ) {
				throw new Exception( 'start_of_week must be 0-6' );
			}
			$items['start_of_week'] = $sow;
		}
		if ( empty( $items ) ) {
			throw new Exception( 'provide date_format, time_format and/or start_of_week' );
		}
		$before = array();
		foreach ( array_keys( $items ) as $n ) {
			$before[ $n ] = get_option( $n );
		}
		return array(
			'before'       => $before,
			'after'        => $items,
			'would_change' => $this->options_would_change( $items ),
			'summary'      => 'date/time format',
			'revert'       => array( 'type' => 'options_set', 'items' => $this->snapshot_options( array_keys( $items ) ) ),
		);
	}
	public function ap_set_date_time_format( $args ) {
		if ( isset( $args['date_format'] ) ) {
			update_option( 'date_format', sanitize_text_field( $args['date_format'] ) );
		}
		if ( isset( $args['time_format'] ) ) {
			update_option( 'time_format', sanitize_text_field( $args['time_format'] ) );
		}
		if ( isset( $args['start_of_week'] ) ) {
			$sow = absint( $args['start_of_week'] );
			if ( $sow > 6 ) {
				throw new Exception( 'start_of_week must be 0-6' );
			}
			update_option( 'start_of_week', $sow );
		}
		return true;
	}

	public function pv_set_discussion_settings( $args ) {
		$items = $this->normalize_discussion( $args );
		if ( empty( $items ) ) {
			throw new Exception( 'provide at least one discussion setting' );
		}
		$before = array();
		foreach ( array_keys( $items ) as $n ) {
			$before[ $n ] = get_option( $n );
		}
		return array(
			'before'       => $before,
			'after'        => $items,
			'would_change' => $this->options_would_change( $items ),
			'summary'      => 'discussion settings: ' . implode( ', ', array_keys( $items ) ),
			'revert'       => array( 'type' => 'options_set', 'items' => $this->snapshot_options( array_keys( $items ) ) ),
		);
	}
	public function ap_set_discussion_settings( $args ) {
		foreach ( $this->normalize_discussion( $args ) as $name => $val ) {
			update_option( $name, $val );
		}
		return true;
	}
	/** Map provided discussion args to sanitized option values. */
	private function normalize_discussion( $args ) {
		$items = array();
		foreach ( $this->discussion_opts as $name => $type ) {
			if ( ! isset( $args[ $name ] ) ) {
				continue;
			}
			$v = $args[ $name ];
			if ( 'onoff' === $type ) {
				$items[ $name ] = $this->truthy( $v ) ? 'open' : 'closed';
			} elseif ( 'bool' === $type ) {
				$items[ $name ] = $this->truthy( $v ) ? '1' : '0';
			} else {
				$n = absint( $v );
				if ( 'comments_per_page' === $name && $n < 1 ) {
					$n = 1;
				}
				$items[ $name ] = (string) $n;
			}
		}
		return $items;
	}
	/** Snapshot a set of options as an options_set revert payload (name/existed/value each). */
	private function snapshot_options( $names ) {
		$out = array();
		foreach ( $names as $name ) {
			$out[] = array( 'name' => $name, 'existed' => ( false !== get_option( $name, false ) ), 'value' => get_option( $name ) );
		}
		return $out;
	}

	private function resolve_theme( $args ) {
		$theme = isset( $args['theme'] ) ? sanitize_text_field( $args['theme'] ) : '';
		if ( '' === $theme ) {
			return get_stylesheet();
		}
		if ( ! wp_get_theme( $theme )->exists() ) {
			throw new Exception( 'theme "' . $theme . '" is not installed' );
		}
		return $theme;
	}
	private function options_would_change( $items ) {
		foreach ( $items as $name => $val ) {
			if ( get_option( $name ) != $val ) {
				return true;
			}
		}
		return false;
	}
	private function theme_mod_revert( $theme, $key ) {
		$mods = get_option( 'theme_mods_' . $theme );
		$mods = is_array( $mods ) ? $mods : array();
		return array( 'type' => 'theme_mod', 'theme' => $theme, 'key' => $key, 'existed' => array_key_exists( $key, $mods ), 'value' => array_key_exists( $key, $mods ) ? $mods[ $key ] : null );
	}

	/** Resolve a nav menu by term_id, slug, or name. Returns WP_Term or false. */
	private function resolve_nav_menu( $menu ) {
		if ( is_array( $menu ) || null === $menu || '' === $menu ) {
			return false;
		}
		$obj = wp_get_nav_menu_object( $menu );
		return $obj ? $obj : false;
	}

	public function op_list_nav_menus( $args ) {
		$menus      = wp_get_nav_menus();
		$locations  = get_nav_menu_locations();
		$registered = get_registered_nav_menus();
		$out = array();
		foreach ( (array) $menus as $m ) {
			$out[] = array( 'term_id' => (int) $m->term_id, 'name' => $m->name, 'slug' => $m->slug, 'count' => (int) $m->count );
		}
		$loc = array();
		foreach ( (array) $registered as $slug => $desc ) {
			$loc[] = array( 'location' => $slug, 'description' => $desc, 'menu_id' => isset( $locations[ $slug ] ) ? (int) $locations[ $slug ] : 0 );
		}
		return array( 'menus' => $out, 'locations' => $loc );
	}
	public function op_get_nav_menu( $args ) {
		$obj = $this->resolve_nav_menu( isset( $args['menu'] ) ? $args['menu'] : '' );
		if ( ! $obj ) {
			throw new Exception( 'menu not found (pass term_id, slug, or name)' );
		}
		$items = wp_get_nav_menu_items( $obj->term_id, array( 'post_status' => 'any' ) );
		if ( ! is_array( $items ) ) {
			$items = array();
		}
		$out = array();
		$n   = 0;
		foreach ( $items as $it ) {
			if ( $n++ >= 500 ) {
				break;
			}
			$out[] = array( 'id' => (int) $it->ID, 'title' => $it->title, 'type' => $it->type, 'object' => $it->object, 'object_id' => (int) $it->object_id, 'url' => $it->url, 'parent' => (int) $it->menu_item_parent, 'menu_order' => (int) $it->menu_order );
		}
		return array( 'term_id' => (int) $obj->term_id, 'name' => $obj->name, 'count' => count( $out ), 'items' => $out );
	}
	public function op_list_sidebars( $args ) {
		global $wp_registered_sidebars;
		$sw  = wp_get_sidebars_widgets();
		$out = array();
		foreach ( (array) $wp_registered_sidebars as $id => $sb ) {
			$out[] = array( 'id' => $id, 'name' => isset( $sb['name'] ) ? $sb['name'] : $id, 'widgets' => isset( $sw[ $id ] ) ? array_values( (array) $sw[ $id ] ) : array() );
		}
		if ( isset( $sw['wp_inactive_widgets'] ) ) {
			$out[] = array( 'id' => 'wp_inactive_widgets', 'name' => 'Inactive Widgets', 'widgets' => array_values( (array) $sw['wp_inactive_widgets'] ) );
		}
		return array( 'block_widgets' => ( function_exists( 'wp_use_widgets_block_editor' ) && wp_use_widgets_block_editor() ), 'sidebars' => $out );
	}
	public function op_get_widget( $args ) {
		$wid = isset( $args['widget_id'] ) ? sanitize_text_field( $args['widget_id'] ) : '';
		if ( '' === $wid ) {
			throw new Exception( 'widget_id is required (e.g. "text-3")' );
		}
		if ( ! preg_match( '/^(.+)-(\d+)$/', $wid, $mm ) ) {
			throw new Exception( 'widget_id must look like base-index, e.g. "text-3"' );
		}
		$base = $mm[1];
		$idx  = (int) $mm[2];
		$opt  = get_option( 'widget_' . $base );
		if ( ! is_array( $opt ) || ! isset( $opt[ $idx ] ) ) {
			return array( 'found' => false, 'widget_id' => $wid );
		}
		return array( 'found' => true, 'widget_id' => $wid, 'base' => $base, 'settings' => $this->cap_size( $this->redact( $base, $opt[ $idx ] ) ) );
	}
	public function op_list_synced_blocks( $args ) {
		$q = array( 'post_type' => 'wp_block', 'post_status' => 'any', 'posts_per_page' => 100, 'suppress_filters' => true, 'no_found_rows' => true );
		if ( ! empty( $args['search'] ) ) {
			$q['s'] = sanitize_text_field( $args['search'] );
		}
		$out = array();
		foreach ( get_posts( $q ) as $p ) {
			$out[] = array( 'id' => $p->ID, 'title' => $p->post_title, 'slug' => $p->post_name, 'status' => $p->post_status );
		}
		return array( 'count' => count( $out ), 'blocks' => $out );
	}

	public function pv_create_nav_menu( $args ) {
		$name = isset( $args['name'] ) ? (string) $args['name'] : '';
		if ( '' === trim( $name ) ) {
			throw new Exception( 'name is required' );
		}
		if ( get_term_by( 'name', $name, 'nav_menu' ) ) {
			throw new Exception( 'a menu named "' . $name . '" already exists' );
		}
		return array( 'before' => null, 'after' => array( 'name' => $name ), 'would_change' => true, 'summary' => sprintf( 'create nav menu "%s"', $name ), 'revert' => null );
	}
	public function ap_create_nav_menu( $args, $preview ) {
		$id = wp_create_nav_menu( $preview['after']['name'] );
		if ( is_wp_error( $id ) ) {
			throw new Exception( $id->get_error_message() );
		}
		return array( 'created' => true, 'term_id' => (int) $id, '_revert' => array( 'type' => 'nav_menu_create', 'term_id' => (int) $id ) );
	}

	public function pv_rename_nav_menu( $args ) {
		$obj = $this->resolve_nav_menu( isset( $args['menu'] ) ? $args['menu'] : '' );
		if ( ! $obj ) {
			throw new Exception( 'menu not found' );
		}
		$name = isset( $args['name'] ) ? (string) $args['name'] : '';
		if ( '' === trim( $name ) ) {
			throw new Exception( 'name is required' );
		}
		$clash = wp_get_nav_menu_object( $name );
		if ( $clash && (int) $clash->term_id !== (int) $obj->term_id ) {
			throw new Exception( 'a menu named "' . $name . '" already exists' );
		}
		return array(
			'before'       => $obj->name,
			'after'        => $name,
			'would_change' => $obj->name !== $name,
			'summary'      => sprintf( 'rename nav menu %d -> "%s"', $obj->term_id, $name ),
			'revert'       => array( 'type' => 'nav_menu_rename', 'term_id' => (int) $obj->term_id, 'name' => $obj->name ),
		);
	}
	public function ap_rename_nav_menu( $args ) {
		$obj = $this->resolve_nav_menu( isset( $args['menu'] ) ? $args['menu'] : '' );
		if ( ! $obj ) {
			throw new Exception( 'menu not found' );
		}
		$res = wp_update_nav_menu_object( $obj->term_id, array( 'menu-name' => (string) $args['name'] ) );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		return true;
	}

	private $nav_item_types = array( 'custom', 'post_type', 'taxonomy', 'post_type_archive' );
	public function pv_add_nav_menu_item( $args ) {
		$obj = $this->resolve_nav_menu( isset( $args['menu'] ) ? $args['menu'] : '' );
		if ( ! $obj ) {
			throw new Exception( 'menu not found' );
		}
		$title = isset( $args['title'] ) ? (string) $args['title'] : '';
		if ( '' === trim( $title ) ) {
			throw new Exception( 'title is required' );
		}
		$type = isset( $args['item_type'] ) ? sanitize_key( $args['item_type'] ) : 'custom';
		if ( ! in_array( $type, $this->nav_item_types, true ) ) {
			throw new Exception( 'item_type must be one of: ' . implode( ', ', $this->nav_item_types ) );
		}
		if ( 'custom' === $type ) {
			if ( ! isset( $args['url'] ) || '' === trim( (string) $args['url'] ) ) {
				throw new Exception( 'url is required for a custom menu item' );
			}
		} elseif ( 'post_type_archive' === $type ) {
			if ( empty( $args['object'] ) ) {
				throw new Exception( 'object (post-type slug) is required for a post_type_archive menu item' );
			}
		} else {
			if ( empty( $args['object_id'] ) ) {
				throw new Exception( 'object_id is required for a ' . $type . ' menu item' );
			}
			if ( empty( $args['object'] ) ) {
				throw new Exception( 'object (post type or taxonomy slug) is required for a ' . $type . ' menu item' );
			}
		}
		return array(
			'before'       => null,
			'after'        => array( 'menu' => (int) $obj->term_id, 'title' => $title, 'item_type' => $type, 'object_id' => isset( $args['object_id'] ) ? absint( $args['object_id'] ) : 0, 'object' => isset( $args['object'] ) ? sanitize_key( $args['object'] ) : '', 'url' => isset( $args['url'] ) ? esc_url_raw( $args['url'] ) : '', 'parent' => isset( $args['parent_item_id'] ) ? absint( $args['parent_item_id'] ) : 0, 'position' => isset( $args['position'] ) ? absint( $args['position'] ) : 0 ),
			'would_change' => true,
			'summary'      => sprintf( 'add menu item "%s" to menu %d', $title, $obj->term_id ),
			'revert'       => null,
		);
	}
	public function ap_add_nav_menu_item( $args, $preview ) {
		$a    = $preview['after'];
		$data = array(
			'menu-item-title'     => $a['title'],
			'menu-item-type'      => $a['item_type'],
			'menu-item-status'    => 'publish',
			'menu-item-parent-id' => $a['parent'],
			'menu-item-position'  => $a['position'],
		);
		if ( 'custom' === $a['item_type'] ) {
			$data['menu-item-url'] = $a['url'];
		} else {
			$data['menu-item-object-id'] = $a['object_id'];
			$data['menu-item-object']    = $a['object'];
		}
		$item_id = wp_update_nav_menu_item( $a['menu'], 0, $data );
		if ( is_wp_error( $item_id ) ) {
			throw new Exception( $item_id->get_error_message() );
		}
		return array( 'created' => true, 'item_id' => (int) $item_id, '_revert' => array( 'type' => 'nav_menu_item', 'item_id' => (int) $item_id ) );
	}

	public function pv_create_synced_block( $args ) {
		$title = isset( $args['title'] ) ? (string) $args['title'] : '';
		if ( '' === trim( $title ) ) {
			throw new Exception( 'title is required' );
		}
		if ( ! isset( $args['content'] ) ) {
			throw new Exception( 'content is required' );
		}
		return array( 'before' => null, 'after' => array( 'title' => $title, 'content' => (string) $args['content'] ), 'would_change' => true, 'summary' => sprintf( 'create synced block "%s"', $title ), 'revert' => null );
	}
	public function ap_create_synced_block( $args, $preview ) {
		$a  = $preview['after'];
		$id = wp_insert_post( array( 'post_type' => 'wp_block', 'post_status' => 'publish', 'post_title' => $a['title'], 'post_content' => $a['content'] ), true );
		if ( is_wp_error( $id ) ) {
			throw new Exception( $id->get_error_message() );
		}
		return array( 'created' => true, 'id' => (int) $id, 'permalink' => get_permalink( $id ), '_revert' => array( 'type' => 'post_create', 'id' => (int) $id ) );
	}

	/** ACF post-id arg: integer post id, or ACF pseudo-ids term_X / user_X / option. */
	private function acf_post_id( $raw ) {
		if ( is_int( $raw ) || ctype_digit( (string) $raw ) ) {
			return absint( $raw );
		}
		return sanitize_text_field( (string) $raw );
	}
	public function op_get_field( $args ) {
		if ( ! function_exists( 'get_field' ) ) {
			throw new Exception( 'ACF is not active' );
		}
		$pid = isset( $args['post_id'] ) ? $this->acf_post_id( $args['post_id'] ) : 0;
		$sel = isset( $args['selector'] ) ? (string) $args['selector'] : '';
		if ( '' === $sel ) {
			throw new Exception( 'selector (field name or key) is required' );
		}
		$fmt = ! isset( $args['format_value'] ) || $this->truthy( $args['format_value'] );
		$val = get_field( $sel, $pid, $fmt );
		$obj = function_exists( 'acf_get_field' ) ? acf_get_field( $sel ) : null;
		return array( 'post_id' => $pid, 'selector' => $sel, 'exists' => ( $obj && ! is_wp_error( $obj ) ), 'value' => $this->cap_size( $this->redact( $sel, $val ) ) );
	}
	public function op_list_field_groups( $args ) {
		if ( ! function_exists( 'acf_get_field_groups' ) ) {
			throw new Exception( 'ACF is not active' );
		}
		$groups = acf_get_field_groups( isset( $args['post_id'] ) ? array( 'post_id' => $this->acf_post_id( $args['post_id'] ) ) : array() );
		$inc = ! empty( $args['include_fields'] );
		$out = array();
		foreach ( (array) $groups as $g ) {
			$row = array( 'key' => $g['key'], 'title' => $g['title'] );
			if ( $inc && function_exists( 'acf_get_fields' ) ) {
				$fl = array();
				foreach ( (array) acf_get_fields( $g['key'] ) as $f ) {
					$fl[] = array( 'key' => $f['key'], 'name' => $f['name'], 'label' => $f['label'], 'type' => $f['type'] );
				}
				$row['fields'] = $fl;
			}
			$out[] = $row;
		}
		return array( 'count' => count( $out ), 'field_groups' => $out );
	}

	private $yoast_keys = array( 'title', 'metadesc', 'focuskw', 'canonical', 'meta-robots-noindex', 'meta-robots-nofollow', 'opengraph-title', 'opengraph-description', 'opengraph-image', 'twitter-title', 'twitter-description', 'twitter-image' );
	private function yoast_active() {
		return defined( 'WPSEO_VERSION' ) || class_exists( 'WPSEO_Meta' ) || class_exists( 'WPSEO_Options' );
	}
	public function pv_yoast_set_meta( $args ) {
		if ( ! $this->yoast_active() ) {
			throw new Exception( 'Yoast SEO is not active' );
		}
		$id = isset( $args['post_id'] ) ? absint( $args['post_id'] ) : 0;
		if ( ! $id || ! get_post( $id ) ) {
			throw new Exception( 'valid post_id is required' );
		}
		$key = isset( $args['key'] ) ? sanitize_text_field( $args['key'] ) : '';
		if ( ! in_array( $key, $this->yoast_keys, true ) ) {
			throw new Exception( 'key must be one of: ' . implode( ', ', $this->yoast_keys ) );
		}
		$value = (string) ( isset( $args['value'] ) ? $args['value'] : '' );
		if ( in_array( $key, array( 'meta-robots-noindex', 'meta-robots-nofollow' ), true ) && ! in_array( $value, array( '0', '1', '2' ), true ) ) {
			throw new Exception( 'robots value must be "0", "1", or "2"' );
		}
		$mk      = '_yoast_wpseo_' . $key;
		$before  = get_post_meta( $id, $mk, true );
		$existed = metadata_exists( 'post', $id, $mk );
		return array(
			'before'       => $before,
			'after'        => $value,
			'would_change' => (string) $before !== $value,
			'summary'      => sprintf( 'Yoast "%s" on post %d', $key, $id ),
			'revert'       => array( 'type' => 'meta', 'id' => $id, 'key' => $mk, 'existed' => $existed, 'value' => $before ),
		);
	}
	public function ap_yoast_set_meta( $args ) {
		if ( ! $this->yoast_active() ) {
			throw new Exception( 'Yoast SEO is not active' );
		}
		$id    = isset( $args['post_id'] ) ? absint( $args['post_id'] ) : 0;
		$key   = isset( $args['key'] ) ? sanitize_text_field( $args['key'] ) : '';
		$value = (string) ( isset( $args['value'] ) ? $args['value'] : '' );
		if ( ! in_array( $key, $this->yoast_keys, true ) ) {
			throw new Exception( 'invalid Yoast key' );
		}
		if ( in_array( $key, array( 'meta-robots-noindex', 'meta-robots-nofollow' ), true ) && ! in_array( $value, array( '0', '1', '2' ), true ) ) {
			throw new Exception( 'robots value must be "0", "1", or "2"' );
		}
		update_post_meta( $id, '_yoast_wpseo_' . $key, $value );
		return true;
	}

	public function pv_set_attachment_fields( $args ) {
		$id = isset( $args['id'] ) ? absint( $args['id'] ) : 0;
		if ( ! $id || 'attachment' !== get_post_type( $id ) ) {
			throw new Exception( 'id must be an attachment' );
		}
		$fields = array();
		foreach ( array( 'alt', 'title', 'caption', 'description' ) as $f ) {
			if ( isset( $args[ $f ] ) ) {
				$fields[ $f ] = ( 'caption' === $f || 'description' === $f ) ? wp_kses_post( $args[ $f ] ) : sanitize_text_field( $args[ $f ] );
			}
		}
		if ( empty( $fields ) ) {
			throw new Exception( 'provide at least one of: alt, title, caption, description' );
		}
		$att = get_post( $id );
		$before = array(
			'alt'         => get_post_meta( $id, '_wp_attachment_image_alt', true ),
			'alt_existed' => metadata_exists( 'post', $id, '_wp_attachment_image_alt' ),
			'title'       => $att->post_title,
			'caption'     => $att->post_excerpt,
			'description' => $att->post_content,
		);
		return array(
			'before'       => array( 'alt' => $before['alt'], 'title' => $before['title'], 'caption' => $before['caption'], 'description' => $before['description'] ),
			'after'        => $fields,
			'would_change' => true,
			'summary'      => sprintf( 'attachment %d fields: %s', $id, implode( ', ', array_keys( $fields ) ) ),
			'revert'       => array( 'type' => 'attachment_fields', 'id' => $id, 'before' => $before ),
		);
	}
	public function ap_set_attachment_fields( $args ) {
		$id = absint( $args['id'] );
		if ( 'attachment' !== get_post_type( $id ) ) {
			throw new Exception( 'not an attachment' );
		}
		$postarr = array( 'ID' => $id );
		if ( isset( $args['title'] ) ) {
			$postarr['post_title'] = sanitize_text_field( $args['title'] );
		}
		if ( isset( $args['caption'] ) ) {
			$postarr['post_excerpt'] = wp_kses_post( $args['caption'] );
		}
		if ( isset( $args['description'] ) ) {
			$postarr['post_content'] = wp_kses_post( $args['description'] );
		}
		if ( count( $postarr ) > 1 ) {
			$res = wp_update_post( $postarr, true );
			if ( is_wp_error( $res ) ) {
				throw new Exception( $res->get_error_message() );
			}
		}
		if ( isset( $args['alt'] ) ) {
			update_post_meta( $id, '_wp_attachment_image_alt', sanitize_text_field( $args['alt'] ) );
		}
		return true;
	}

	public function pv_attach_to_post( $args ) {
		$id = isset( $args['id'] ) ? absint( $args['id'] ) : 0;
		if ( ! $id || 'attachment' !== get_post_type( $id ) ) {
			throw new Exception( 'id must be an attachment' );
		}
		$pid = isset( $args['post_id'] ) ? absint( $args['post_id'] ) : 0;
		if ( ! $pid || ! get_post( $pid ) ) {
			throw new Exception( 'valid post_id is required' );
		}
		$feat = ! empty( $args['set_as_featured'] );
		if ( $feat && ! wp_attachment_is_image( $id ) ) {
			throw new Exception( 'cannot set a non-image as a featured image' );
		}
		$prev_parent = (int) get_post( $id )->post_parent;
		$revert = array( 'type' => 'attachment_parent', 'id' => $id, 'prev_parent' => $prev_parent );
		if ( $feat ) {
			$revert['featured_post']     = $pid;
			$revert['prev_thumb']        = get_post_meta( $pid, '_thumbnail_id', true );
			$revert['prev_thumb_existed']= metadata_exists( 'post', $pid, '_thumbnail_id' );
		}
		return array(
			'before'       => array( 'parent' => $prev_parent ),
			'after'        => array( 'parent' => $pid, 'set_as_featured' => $feat ),
			'would_change' => true,
			'summary'      => sprintf( 'attach %d to post %d%s', $id, $pid, $feat ? ' + featured' : '' ),
			'revert'       => $revert,
		);
	}
	public function ap_attach_to_post( $args ) {
		$id  = absint( $args['id'] );
		$pid = absint( $args['post_id'] );
		$feat= ! empty( $args['set_as_featured'] );
		if ( 'attachment' !== get_post_type( $id ) ) {
			throw new Exception( 'not an attachment' );
		}
		$res = wp_update_post( array( 'ID' => $id, 'post_parent' => $pid ), true );
		if ( is_wp_error( $res ) ) {
			throw new Exception( $res->get_error_message() );
		}
		if ( $feat ) {
			if ( ! wp_attachment_is_image( $id ) ) {
				throw new Exception( 'not an image attachment' );
			}
			set_post_thumbnail( $pid, $id );
		}
		return true;
	}

	public function pv_recount_terms( $args ) {
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		$ids = ! empty( $args['term_ids'] ) ? array_map( 'absint', (array) $args['term_ids'] ) : array();
		if ( '' === $tax && empty( $ids ) ) {
			throw new Exception( 'provide taxonomy and/or term_ids' );
		}
		if ( '' !== $tax && ! taxonomy_exists( $tax ) ) {
			throw new Exception( 'taxonomy does not exist' );
		}
		return array( 'before' => null, 'after' => null, 'would_change' => true, 'summary' => '' !== $tax ? ( 'recount terms in ' . $tax ) : ( 'recount ' . count( $ids ) . ' terms' ), 'revert' => null );
	}
	public function ap_recount_terms( $args ) {
		$tax = isset( $args['taxonomy'] ) ? sanitize_key( $args['taxonomy'] ) : '';
		$ids = ! empty( $args['term_ids'] ) ? array_map( 'absint', (array) $args['term_ids'] ) : array();
		$buckets = array();
		if ( $ids ) {
			foreach ( $ids as $tid ) {
				$t = get_term( $tid );
				if ( $t && ! is_wp_error( $t ) ) {
					$buckets[ $t->taxonomy ][] = (int) $t->term_taxonomy_id;
				}
			}
		} elseif ( $tax ) {
			$ttids = get_terms( array( 'taxonomy' => $tax, 'hide_empty' => false, 'fields' => 'tt_ids' ) );
			if ( ! is_wp_error( $ttids ) && $ttids ) {
				$buckets[ $tax ] = array_map( 'intval', (array) $ttids );
			}
		}
		$n = 0;
		foreach ( $buckets as $tx => $ttids ) {
			wp_update_term_count_now( $ttids, $tx );
			$n += count( $ttids );
		}
		return array( 'recounted' => $n );
	}

	public function pv_delete_transient( $args ) {
		$key = isset( $args['key'] ) ? sanitize_text_field( $args['key'] ) : '';
		if ( '' === $key ) {
			throw new Exception( 'key is required' );
		}
		if ( 0 === strpos( $key, 'h_ops_' ) ) {
			throw new Exception( 'refusing to delete JB Ops internal transients' );
		}
		$sw     = ! empty( $args['site_wide'] );
		$before = $sw ? get_site_transient( $key ) : get_transient( $key );
		return array(
			'before'       => $this->cap_size( $this->redact( $key, $before ) ),
			'after'        => null,
			'would_change' => ( false !== $before ),
			'summary'      => sprintf( 'delete %stransient "%s"', $sw ? 'site ' : '', $key ),
			'revert'       => null,
		);
	}
	public function ap_delete_transient( $args ) {
		$key = sanitize_text_field( $args['key'] );
		if ( 0 === strpos( $key, 'h_ops_' ) ) {
			throw new Exception( 'refusing to delete JB Ops internal transients' );
		}
		if ( ! empty( $args['site_wide'] ) ) {
			delete_site_transient( $key );
		} else {
			delete_transient( $key );
		}
		return true;
	}

	public function pv_clear_cache( $args ) {
		return array( 'before' => null, 'after' => null, 'would_change' => true, 'summary' => 'flush caches (object cache + detected page caches + optional opcache)', 'revert' => null );
	}
	public function ap_clear_cache( $args ) {
		$done = array();
		wp_cache_flush();
		$done['object_cache'] = true;
		if ( ! empty( $args['opcache'] ) && function_exists( 'opcache_reset' ) ) {
			$done['opcache'] = (bool) @opcache_reset();
		}
		if ( function_exists( 'wp_cache_clear_cache' ) ) {
			wp_cache_clear_cache();
			$done['wp_super_cache'] = true;
		}
		if ( function_exists( 'rocket_clean_domain' ) ) {
			rocket_clean_domain();
			$done['wp_rocket'] = true;
		}
		return array( 'cleared' => $done );
	}

	public function op_get_field_layouts( $args ) {
		if ( ! function_exists( 'acf_get_field' ) ) {
			throw new Exception( 'ACF is not active' );
		}
		$sel = isset( $args['field'] ) ? (string) $args['field'] : '';
		if ( '' === $sel ) {
			throw new Exception( 'field (name or key) is required' );
		}
		$pid = isset( $args['post_id'] ) ? $this->acf_post_id( $args['post_id'] ) : 0;
		$f   = ( $pid && function_exists( 'get_field_object' ) ) ? get_field_object( $sel, $pid, false, false ) : acf_get_field( $sel );
		if ( ! $f || empty( $f['key'] ) ) {
			throw new Exception( 'field not found (pass post_id with a field name, or a field key)' );
		}
		$out = array( 'key' => $f['key'], 'name' => $f['name'], 'type' => $f['type'], 'label' => isset( $f['label'] ) ? $f['label'] : '' );
		if ( 'flexible_content' === $f['type'] ) {
			$layouts = array();
			foreach ( (array) ( isset( $f['layouts'] ) ? $f['layouts'] : array() ) as $lay ) {
				$subs = array();
				foreach ( (array) ( isset( $lay['sub_fields'] ) ? $lay['sub_fields'] : array() ) as $sf ) {
					$subs[] = array( 'name' => $sf['name'], 'key' => $sf['key'], 'label' => $sf['label'], 'type' => $sf['type'] );
				}
				$layouts[] = array( 'name' => $lay['name'], 'label' => isset( $lay['label'] ) ? $lay['label'] : $lay['name'], 'sub_fields' => $subs );
			}
			$out['layouts'] = $layouts;
		} elseif ( in_array( $f['type'], array( 'repeater', 'group' ), true ) ) {
			$subs = array();
			foreach ( (array) ( isset( $f['sub_fields'] ) ? $f['sub_fields'] : array() ) as $sf ) {
				$subs[] = array( 'name' => $sf['name'], 'key' => $sf['key'], 'label' => $sf['label'], 'type' => $sf['type'] );
			}
			$out['sub_fields'] = $subs;
		}
		return $out;
	}

	/** Resolve an ACF field object for a selector on a given post; returns [object|null, key]. */
	private function acf_resolve_field( $sel, $pid ) {
		$fo = function_exists( 'get_field_object' ) ? get_field_object( $sel, $pid, false, false ) : null;
		if ( ( ! $fo || empty( $fo['key'] ) ) && function_exists( 'acf_get_field' ) ) {
			$fo = acf_get_field( $sel );
		}
		$key = ( $fo && ! empty( $fo['key'] ) ) ? $fo['key'] : '';
		return array( $fo, $key );
	}
	/** Recursively kses_post string leaf values (ACF's programmatic update_field applies no kses; bridge is logged-out). */
	private function sanitize_acf_value( $v ) {
		if ( is_string( $v ) ) {
			// Only sanitize strings that actually contain markup; leaves URLs (with &), JSON, and plain text byte-intact.
			return ( false !== strpos( $v, '<' ) ) ? wp_kses_post( $v ) : $v;
		}
		if ( is_array( $v ) ) {
			$out = array();
			foreach ( $v as $k => $vv ) {
				$out[ $k ] = $this->sanitize_acf_value( $vv );
			}
			return $out;
		}
		return $v;
	}
	public function pv_update_field( $args ) {
		if ( ! function_exists( 'update_field' ) ) {
			throw new Exception( 'ACF is not active' );
		}
		$pid = isset( $args['post_id'] ) ? $this->acf_post_id( $args['post_id'] ) : 0;
		if ( '' === (string) $pid || 0 === $pid ) {
			throw new Exception( 'post_id is required (a post id, term_X, or option)' );
		}
		// Refuse user_X targets: ACF would write USER META, bypassing blocked_meta_key
		// (capabilities/roles/session_tokens) — a privilege-escalation side-channel.
		if ( is_string( $pid ) && 0 === stripos( $pid, 'user_' ) ) {
			throw new Exception( 'writing ACF fields on user objects (user_X) is not allowed via the bridge' );
		}
		$sel = isset( $args['selector'] ) ? (string) $args['selector'] : '';
		if ( '' === $sel ) {
			throw new Exception( 'selector (field name or key) is required' );
		}
		if ( ! array_key_exists( 'value', $args ) ) {
			throw new Exception( 'value is required' );
		}
		list( $fo, $key ) = $this->acf_resolve_field( $sel, $pid );
		if ( '' === $key ) {
			throw new Exception( 'ACF field "' . $sel . '" not found for this post (use get_field_layouts / list_field_groups to discover field names & keys)' );
		}
		$before = get_field( $key, $pid, false ); // raw prior value (whole array for flexible/repeater)
		return array(
			'before'       => $this->cap_size( $this->redact( $sel, $before ) ),
			'after'        => $this->cap_size( $this->redact( $sel, $this->sanitize_acf_value( $args['value'] ) ) ),
			'would_change' => true,
			'summary'      => sprintf( 'ACF field "%s" (%s) on %s', $sel, $key, (string) $pid ),
			'revert'       => array( 'type' => 'acf_field', 'post_id' => $pid, 'key' => $key, 'value' => $before ),
		);
	}
	public function ap_update_field( $args ) {
		if ( ! function_exists( 'update_field' ) ) {
			throw new Exception( 'ACF is not active' );
		}
		$pid = $this->acf_post_id( $args['post_id'] );
		if ( is_string( $pid ) && 0 === stripos( $pid, 'user_' ) ) {
			throw new Exception( 'writing ACF fields on user objects (user_X) is not allowed via the bridge' );
		}
		$sel = (string) $args['selector'];
		list( $fo, $key ) = $this->acf_resolve_field( $sel, $pid );
		if ( '' === $key ) {
			throw new Exception( 'ACF field not found for this post' );
		}
		$ok = update_field( $key, $this->sanitize_acf_value( $args['value'] ), $pid );
		if ( function_exists( 'acf_flush_value_cache' ) ) {
			acf_flush_value_cache( $pid, $key );
		}
		return array( 'updated' => (bool) $ok, 'field_key' => $key );
	}

	/** SSRF guard for server-side fetches: http/https only + WP's private/reserved-IP validation. */
	private function assert_safe_remote_url( $url ) {
		$url    = esc_url_raw( (string) $url );
		$scheme = strtolower( (string) wp_parse_url( $url, PHP_URL_SCHEME ) );
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			throw new Exception( 'only http/https URLs are allowed' );
		}
		if ( ! wp_http_validate_url( $url ) ) {
			throw new Exception( 'url failed safety validation (malformed, or resolves to a private/reserved address)' );
		}
		// wp_http_validate_url misses 169.254.0.0/16 (cloud metadata) and ALL of IPv6.
		// Resolve every A/AAAA and reject any private or reserved address ourselves.
		$host = (string) wp_parse_url( $url, PHP_URL_HOST );
		foreach ( $this->resolve_ips( $host ) as $ip ) {
			if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
				throw new Exception( 'url resolves to a private/reserved/link-local address' );
			}
		}
		return $url;
	}

	/** Resolve a host to all its IPv4+IPv6 addresses (literal IPs pass through). */
	private function resolve_ips( $host ) {
		$host = trim( (string) $host, '[]' );
		if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return array( $host );
		}
		$ips = array();
		$v4  = @gethostbynamel( $host );
		if ( is_array( $v4 ) ) {
			$ips = array_merge( $ips, $v4 );
		}
		if ( function_exists( 'dns_get_record' ) ) {
			$v6 = @dns_get_record( $host, DNS_AAAA );
			if ( is_array( $v6 ) ) {
				foreach ( $v6 as $r ) {
					if ( ! empty( $r['ipv6'] ) ) {
						$ips[] = $r['ipv6'];
					}
				}
			}
		}
		if ( empty( $ips ) ) {
			throw new Exception( 'could not resolve host for safety validation' );
		}
		return array_unique( $ips );
	}
	private function load_media_includes() {
		require_once ABSPATH . 'wp-admin/includes/file.php';
		require_once ABSPATH . 'wp-admin/includes/media.php';
		require_once ABSPATH . 'wp-admin/includes/image.php';
	}
	/** Shared sideload finish: validate image MIME, create attachment, set fields/featured, return result + revert. */
	private function finish_sideload( $file, $args, $after ) {
		$ft      = wp_check_filetype_and_ext( $file['tmp_name'], $file['name'] );
		$type    = isset( $ft['type'] ) ? $ft['type'] : '';
		$allowed = array( 'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/avif' );
		if ( ! in_array( $type, $allowed, true ) ) {
			@unlink( $file['tmp_name'] );
			throw new Exception( 'only raster images are allowed (jpeg/png/gif/webp/avif); got: ' . ( $type ? $type : 'unknown' ) . ( 'image/svg+xml' === $type ? ' — SVG is rejected (script risk)' : '' ) );
		}
		$post_data = array();
		if ( isset( $args['title'] ) ) {
			$post_data['post_title'] = sanitize_text_field( $args['title'] );
		}
		if ( isset( $args['caption'] ) ) {
			$post_data['post_excerpt'] = wp_kses_post( $args['caption'] );
		}
		if ( isset( $args['description'] ) ) {
			$post_data['post_content'] = wp_kses_post( $args['description'] );
		}
		$pid    = ! empty( $after['post_id'] ) ? (int) $after['post_id'] : 0;
		$att_id = media_handle_sideload( $file, $pid, null, $post_data );
		if ( is_wp_error( $att_id ) ) {
			@unlink( $file['tmp_name'] );
			throw new Exception( 'sideload failed: ' . $att_id->get_error_message() );
		}
		if ( isset( $args['alt'] ) ) {
			update_post_meta( $att_id, '_wp_attachment_image_alt', sanitize_text_field( $args['alt'] ) );
		}
		$revert = array( 'type' => 'attachment_create', 'id' => (int) $att_id );
		if ( ! empty( $after['set_as_featured'] ) && $pid ) {
			$revert['featured_post']      = $pid;
			$revert['prev_thumb']         = get_post_meta( $pid, '_thumbnail_id', true );
			$revert['prev_thumb_existed'] = metadata_exists( 'post', $pid, '_thumbnail_id' );
			set_post_thumbnail( $pid, $att_id );
		}
		return array( 'created' => true, 'id' => (int) $att_id, 'url' => wp_get_attachment_url( $att_id ), '_revert' => $revert );
	}

	public function pv_sideload_image( $args ) {
		$url  = $this->assert_safe_remote_url( isset( $args['url'] ) ? $args['url'] : '' );
		$pid  = isset( $args['post_id'] ) ? absint( $args['post_id'] ) : 0;
		if ( $pid && ! get_post( $pid ) ) {
			throw new Exception( 'post_id does not exist' );
		}
		$feat = ! empty( $args['set_as_featured'] );
		if ( $feat && ! $pid ) {
			throw new Exception( 'set_as_featured requires a post_id' );
		}
		return array(
			'before'       => null,
			'after'        => array( 'url' => $url, 'post_id' => $pid, 'set_as_featured' => $feat, 'filename' => isset( $args['filename'] ) ? sanitize_file_name( $args['filename'] ) : '' ),
			'would_change' => true,
			'summary'      => sprintf( 'sideload image from %s%s', $url, $feat ? ( ' as featured of post ' . $pid ) : '' ),
			'revert'       => null,
		);
	}
	public function ap_sideload_image( $args, $preview ) {
		$a = $preview['after'];
		$this->load_media_includes();
		$url = $this->assert_safe_remote_url( $a['url'] ); // re-validate at apply time
		// Disable redirect-following + reject unsafe hops for THIS fetch: a 30x to an
		// internal address (169.254.x, 127.x, ::1) is the classic way to defeat URL
		// validation. With redirection=0 the redirect body isn't an image and is rejected.
		$harden = function ( $a ) {
			$a['redirection']        = 0;
			$a['reject_unsafe_urls'] = true;
			return $a;
		};
		add_filter( 'http_request_args', $harden, 99 );
		try {
			$tmp = download_url( $url, 30 );
		} finally {
			remove_filter( 'http_request_args', $harden, 99 );
		}
		if ( is_wp_error( $tmp ) ) {
			throw new Exception( 'download failed: ' . $tmp->get_error_message() );
		}
		$name = '' !== $a['filename'] ? $a['filename'] : basename( (string) wp_parse_url( $url, PHP_URL_PATH ) );
		if ( '' === $name ) {
			$name = 'image';
		}
		return $this->finish_sideload( array( 'name' => $name, 'tmp_name' => $tmp ), $args, $a );
	}

	public function pv_upload_image_base64( $args ) {
		if ( empty( $args['data'] ) ) {
			throw new Exception( 'data (base64) is required' );
		}
		if ( empty( $args['filename'] ) ) {
			throw new Exception( 'filename is required' );
		}
		if ( strlen( (string) $args['data'] ) > 20 * 1024 * 1024 ) {
			throw new Exception( 'base64 payload too large (>20MB encoded)' );
		}
		$pid = isset( $args['post_id'] ) ? absint( $args['post_id'] ) : 0;
		if ( $pid && ! get_post( $pid ) ) {
			throw new Exception( 'post_id does not exist' );
		}
		return array(
			'before'       => null,
			'after'        => array( 'filename' => sanitize_file_name( $args['filename'] ), 'post_id' => $pid, 'set_as_featured' => ! empty( $args['set_as_featured'] ) && $pid ),
			'would_change' => true,
			'summary'      => sprintf( 'upload image "%s"', sanitize_file_name( $args['filename'] ) ),
			'revert'       => null,
		);
	}
	public function ap_upload_image_base64( $args, $preview ) {
		$a = $preview['after'];
		$this->load_media_includes();
		$raw = base64_decode( (string) $args['data'], true );
		if ( false === $raw ) {
			throw new Exception( 'data is not valid base64' );
		}
		if ( strlen( $raw ) > 15 * 1024 * 1024 ) {
			throw new Exception( 'decoded image too large (>15MB)' );
		}
		$name = '' !== $a['filename'] ? $a['filename'] : 'image';
		$tmp  = wp_tempnam( $name );
		if ( ! $tmp ) {
			throw new Exception( 'could not create a temp file' );
		}
		if ( false === file_put_contents( $tmp, $raw ) ) {
			@unlink( $tmp );
			throw new Exception( 'could not write the decoded image' );
		}
		return $this->finish_sideload( array( 'name' => $name, 'tmp_name' => $tmp ), $args, $a );
	}

	/** Snapshot a nav menu item's current values in wp_update_nav_menu_item() arg shape. */
	private function nav_item_snapshot( $iid ) {
		$post = get_post( $iid );
		$i    = wp_setup_nav_menu_item( $post );
		return array(
			'menu-item-title'       => $post->post_title,
			'menu-item-url'         => $i->url,
			'menu-item-object-id'   => (int) $i->object_id,
			'menu-item-object'      => $i->object,
			'menu-item-type'        => $i->type,
			'menu-item-parent-id'   => (int) $i->menu_item_parent,
			'menu-item-position'    => (int) $i->menu_order,
			'menu-item-target'      => $i->target,
			'menu-item-attr-title'  => $post->post_excerpt,
			'menu-item-description' => $post->post_content,
			'menu-item-classes'     => is_array( $i->classes ) ? implode( ' ', $i->classes ) : (string) $i->classes,
			'menu-item-xfn'         => $i->xfn,
			'menu-item-status'      => 'publish',
		);
	}
	/** Resolve the nav_menu term id a menu item belongs to (0 if none). */
	private function nav_item_menu_id( $iid ) {
		$terms = wp_get_object_terms( $iid, 'nav_menu', array( 'fields' => 'ids' ) );
		return ( ! is_wp_error( $terms ) && $terms ) ? (int) $terms[0] : 0;
	}

	public function pv_update_nav_menu_item( $args ) {
		$iid = isset( $args['item_id'] ) ? absint( $args['item_id'] ) : 0;
		if ( ! $iid || 'nav_menu_item' !== get_post_type( $iid ) ) {
			throw new Exception( 'item_id must be a nav menu item' );
		}
		$menu_id = $this->nav_item_menu_id( $iid );
		if ( ! $menu_id ) {
			throw new Exception( 'could not resolve the menu for this item' );
		}
		$before = $this->nav_item_snapshot( $iid );
		return array(
			'before'       => $before,
			'after'        => array_intersect_key( $args, array_flip( array( 'title', 'url', 'object_id', 'parent_item_id', 'position', 'target', 'classes' ) ) ),
			'would_change' => true,
			'summary'      => sprintf( 'update menu item %d (menu %d)', $iid, $menu_id ),
			'revert'       => array( 'type' => 'nav_menu_item_update', 'menu_id' => $menu_id, 'item_id' => $iid, 'before' => $before ),
		);
	}
	public function ap_update_nav_menu_item( $args ) {
		$iid = absint( $args['item_id'] );
		if ( 'nav_menu_item' !== get_post_type( $iid ) ) {
			throw new Exception( 'not a nav menu item' );
		}
		$menu_id = $this->nav_item_menu_id( $iid );
		if ( ! $menu_id ) {
			throw new Exception( 'menu not resolved' );
		}
		$data = $this->nav_item_snapshot( $iid );
		if ( isset( $args['title'] ) ) {
			$data['menu-item-title'] = sanitize_text_field( $args['title'] );
		}
		if ( isset( $args['url'] ) ) {
			$data['menu-item-url'] = esc_url_raw( $args['url'] );
		}
		if ( isset( $args['object_id'] ) ) {
			$data['menu-item-object-id'] = absint( $args['object_id'] );
		}
		if ( isset( $args['parent_item_id'] ) ) {
			$data['menu-item-parent-id'] = absint( $args['parent_item_id'] );
		}
		if ( isset( $args['position'] ) ) {
			$data['menu-item-position'] = absint( $args['position'] );
		}
		if ( isset( $args['target'] ) ) {
			$data['menu-item-target'] = ( '_blank' === $args['target'] ) ? '_blank' : '';
		}
		if ( isset( $args['classes'] ) ) {
			$data['menu-item-classes'] = sanitize_text_field( $args['classes'] );
		}
		$r = wp_update_nav_menu_item( $menu_id, $iid, $data );
		if ( is_wp_error( $r ) ) {
			throw new Exception( $r->get_error_message() );
		}
		return true;
	}

	public function pv_remove_nav_menu_item( $args ) {
		$iid = isset( $args['item_id'] ) ? absint( $args['item_id'] ) : 0;
		if ( ! $iid || 'nav_menu_item' !== get_post_type( $iid ) ) {
			throw new Exception( 'item_id must be a nav menu item' );
		}
		$menu_id = $this->nav_item_menu_id( $iid );
		$kids = get_posts( array( 'post_type' => 'nav_menu_item', 'meta_key' => '_menu_item_menu_item_parent', 'meta_value' => (string) $iid, 'posts_per_page' => 1, 'fields' => 'ids', 'suppress_filters' => true ) );
		$before = $this->nav_item_snapshot( $iid );
		return array(
			'before'       => $before,
			'after'        => null,
			'would_change' => true,
			'summary'      => sprintf( 'remove menu item %d%s', $iid, $kids ? ' (WARNING: has child items that will be orphaned)' : '' ),
			'revert'       => array( 'type' => 'nav_menu_item_recreate', 'menu_id' => $menu_id, 'before' => $before ),
		);
	}
	public function ap_remove_nav_menu_item( $args ) {
		$iid = absint( $args['item_id'] );
		if ( 'nav_menu_item' !== get_post_type( $iid ) ) {
			throw new Exception( 'not a nav menu item' );
		}
		wp_delete_post( $iid, true );
		return true;
	}

	public function pv_reorder_nav_menu_items( $args ) {
		$obj = $this->resolve_nav_menu( isset( $args['menu'] ) ? $args['menu'] : '' );
		if ( ! $obj ) {
			throw new Exception( 'menu not found' );
		}
		if ( empty( $args['order'] ) || ! is_array( $args['order'] ) ) {
			throw new Exception( 'order (array of item_ids) is required' );
		}
		$order = array_map( 'absint', $args['order'] );
		$items = wp_get_nav_menu_items( $obj->term_id, array( 'post_status' => 'any' ) );
		$current = array();
		$before  = array();
		foreach ( (array) $items as $i ) {
			$current[] = (int) $i->ID;
			$before[ (int) $i->ID ] = (int) $i->menu_order;
		}
		foreach ( $order as $iid ) {
			if ( ! in_array( $iid, $current, true ) ) {
				throw new Exception( 'item ' . $iid . ' is not in this menu' );
			}
		}
		if ( count( $order ) !== count( array_unique( $order ) ) ) {
			throw new Exception( 'order contains duplicate item ids' );
		}
		if ( count( $order ) !== count( $current ) ) {
			throw new Exception( 'order must list ALL ' . count( $current ) . ' items currently in this menu (a full permutation)' );
		}
		return array(
			'before'       => $before,
			'after'        => $order,
			'would_change' => ( $order !== $current ),
			'summary'      => sprintf( 'reorder %d items in menu %d', count( $order ), $obj->term_id ),
			'revert'       => array( 'type' => 'nav_menu_order', 'items' => $before ),
		);
	}
	public function ap_reorder_nav_menu_items( $args ) {
		$order = array_map( 'absint', $args['order'] );
		$pos = 1;
		foreach ( $order as $iid ) {
			$r = wp_update_post( array( 'ID' => $iid, 'menu_order' => $pos++ ), true );
			if ( is_wp_error( $r ) ) {
				throw new Exception( $r->get_error_message() );
			}
		}
		return true;
	}

	public function pv_assign_nav_menu_location( $args ) {
		$loc = isset( $args['location'] ) ? sanitize_key( $args['location'] ) : '';
		$registered = get_registered_nav_menus();
		if ( '' === $loc || ! isset( $registered[ $loc ] ) ) {
			throw new Exception( 'location must be a registered theme menu location: ' . implode( ', ', array_keys( $registered ) ) );
		}
		$menu_id = 0;
		if ( isset( $args['menu'] ) && '' !== $args['menu'] && 0 !== $args['menu'] && '0' !== (string) $args['menu'] ) {
			$obj = $this->resolve_nav_menu( $args['menu'] );
			if ( ! $obj ) {
				throw new Exception( 'menu not found' );
			}
			$menu_id = (int) $obj->term_id;
		}
		$locations = get_nav_menu_locations();
		$locations = is_array( $locations ) ? $locations : array();
		return array(
			'before'       => isset( $locations[ $loc ] ) ? (int) $locations[ $loc ] : 0,
			'after'        => $menu_id,
			'would_change' => ( isset( $locations[ $loc ] ) ? (int) $locations[ $loc ] : 0 ) !== $menu_id,
			'summary'      => $menu_id ? sprintf( 'assign menu %d to location "%s"', $menu_id, $loc ) : sprintf( 'clear menu location "%s"', $loc ),
			'revert'       => array( 'type' => 'nav_menu_locations', 'value' => $locations ),
		);
	}
	public function ap_assign_nav_menu_location( $args ) {
		$loc = sanitize_key( $args['location'] );
		$registered = get_registered_nav_menus();
		if ( ! isset( $registered[ $loc ] ) ) {
			throw new Exception( 'unregistered location' );
		}
		$locations = get_nav_menu_locations();
		$locations = is_array( $locations ) ? $locations : array();
		if ( isset( $args['menu'] ) && '' !== $args['menu'] && 0 !== $args['menu'] && '0' !== (string) $args['menu'] ) {
			$obj = $this->resolve_nav_menu( $args['menu'] );
			if ( ! $obj ) {
				throw new Exception( 'menu not found' );
			}
			$locations[ $loc ] = (int) $obj->term_id;
		} else {
			unset( $locations[ $loc ] );
		}
		set_theme_mod( 'nav_menu_locations', $locations );
		return true;
	}

	/** Validate a plugin file path (folder/file.php or file.php), no traversal. */
	private function sanitize_plugin_file( $p ) {
		$p = ltrim( str_replace( '\\', '/', (string) $p ), '/' );
		if ( '' === $p || false !== strpos( $p, '..' ) ) {
			throw new Exception( 'invalid plugin path' );
		}
		if ( ! preg_match( '#^[A-Za-z0-9 ._-]+/[A-Za-z0-9 ._-]+\.php$#', $p ) && ! preg_match( '#^[A-Za-z0-9 ._-]+\.php$#', $p ) ) {
			throw new Exception( 'plugin must be "folder/file.php" (or "file.php" for a single-file plugin)' );
		}
		return $p;
	}
	/** Activate a plugin with a sandbox scrape first, so a fatal-on-load dies the request BEFORE the plugin is marked active (no persistent WSOD). */
	private function safe_activate_plugin( $plugin, $network_wide = false ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		try {
			plugin_sandbox_scrape( $plugin );
		} catch ( \Throwable $e ) {
			throw new Exception( 'plugin fatals on load; refusing to activate: ' . $e->getMessage() );
		}
		$res = activate_plugin( $plugin, '', (bool) $network_wide );
		if ( is_wp_error( $res ) ) {
			throw new Exception( 'activation failed: ' . $res->get_error_message() );
		}
	}
	public function pv_activate_plugin( $args ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugin = isset( $args['plugin'] ) ? $this->sanitize_plugin_file( $args['plugin'] ) : '';
		if ( ! isset( get_plugins()[ $plugin ] ) ) {
			throw new Exception( 'plugin "' . $plugin . '" is not installed' );
		}
		if ( is_plugin_active( $plugin ) ) {
			return array( 'before' => 'active', 'after' => 'active', 'would_change' => false, 'summary' => $plugin . ' is already active', 'revert' => null );
		}
		return array(
			'before'       => 'inactive',
			'after'        => 'active',
			'would_change' => true,
			'summary'      => 'activate plugin ' . $plugin . ' (note: a fatal in the plugin can white-screen the site; revert deactivates it)',
			'revert'       => array( 'type' => 'plugin_state', 'plugin' => $plugin, 'action' => 'activated', 'network' => false ),
		);
	}
	public function ap_activate_plugin( $args ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugin = $this->sanitize_plugin_file( $args['plugin'] );
		if ( ! isset( get_plugins()[ $plugin ] ) ) {
			throw new Exception( 'plugin is not installed' );
		}
		if ( is_plugin_active( $plugin ) ) {
			return array( 'activated' => true, 'plugin' => $plugin, 'already' => true );
		}
		$this->safe_activate_plugin( $plugin );
		return array( 'activated' => true, 'plugin' => $plugin );
	}
	public function pv_deactivate_plugin( $args ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugin = isset( $args['plugin'] ) ? $this->sanitize_plugin_file( $args['plugin'] ) : '';
		if ( $plugin === plugin_basename( __FILE__ ) ) {
			throw new Exception( 'refusing to deactivate JB Ops itself (would brick the bridge and its revert path)' );
		}
		if ( ! isset( get_plugins()[ $plugin ] ) ) {
			throw new Exception( 'plugin "' . $plugin . '" is not installed' );
		}
		if ( ! is_plugin_active( $plugin ) ) {
			return array( 'before' => 'inactive', 'after' => 'inactive', 'would_change' => false, 'summary' => $plugin . ' is already inactive', 'revert' => null );
		}
		if ( is_plugin_active_for_network( $plugin ) && empty( $args['network'] ) ) {
			throw new Exception( 'plugin is network-active; pass network:true to deactivate it network-wide' );
		}
		return array(
			'before'       => 'active',
			'after'        => 'inactive',
			'would_change' => true,
			'summary'      => 'deactivate plugin ' . $plugin,
			'revert'       => array( 'type' => 'plugin_state', 'plugin' => $plugin, 'action' => 'deactivated', 'network' => ! empty( $args['network'] ) ),
		);
	}
	public function ap_deactivate_plugin( $args ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		$plugin = $this->sanitize_plugin_file( $args['plugin'] );
		if ( $plugin === plugin_basename( __FILE__ ) ) {
			throw new Exception( 'refusing to deactivate JB Ops itself' );
		}
		deactivate_plugins( $plugin, false, ! empty( $args['network'] ) );
		return array( 'deactivated' => true, 'plugin' => $plugin );
	}

	public function pv_set_permalink( $args ) {
		$id = isset( $args['post_id'] ) ? absint( $args['post_id'] ) : 0;
		if ( ! $id || ! get_post( $id ) ) {
			throw new Exception( 'valid post_id is required' );
		}
		if ( ! isset( $args['uri'] ) || '' === trim( (string) $args['uri'] ) ) {
			throw new Exception( 'uri is required' );
		}
		$uri  = trim( (string) $args['uri'], '/' );
		$uris = get_option( 'permalink-manager-uris' );
		if ( ! is_array( $uris ) ) {
			throw new Exception( 'Permalink Manager is not active (permalink-manager-uris missing)' );
		}
		$before = $uris[ $id ] ?? null;
		return array(
			'before'       => $before,
			'after'        => $uri,
			'would_change' => $before !== $uri,
			'summary'      => sprintf( 'Permalink Manager URI for post %d', $id ),
			'revert'       => array( 'type' => 'permalink', 'post_id' => $id, 'existed' => isset( $uris[ $id ] ), 'value' => $before ),
		);
	}
	public function ap_set_permalink( $args ) {
		$id   = absint( $args['post_id'] );
		$uri  = trim( (string) $args['uri'], '/' );
		$uris = get_option( 'permalink-manager-uris' );
		if ( ! is_array( $uris ) ) {
			throw new Exception( 'permalink-manager-uris missing' );
		}
		$uris[ $id ] = $uri;
		update_option( 'permalink-manager-uris', $uris );
		return true;
	}

	public function pv_flush_rewrite( $args ) {
		return array(
			'before'       => null,
			'after'        => null,
			'would_change' => true,
			'summary'      => 'flush rewrite rules',
			'revert'       => null, // not revertible (rules are regenerated)
		);
	}
	public function ap_flush_rewrite( $args ) {
		flush_rewrite_rules( true );
		return true;
	}

	/** Apply a stored revert payload. */
	private function restore( $p ) {
		switch ( $p['type'] ?? '' ) {
			case 'meta':
				if ( $this->blocked_meta_key( $p['key'] ) ) {
					throw new Exception( 'refusing to restore a blocked meta key' );
				}
				if ( empty( $p['existed'] ) ) {
					delete_post_meta( $p['id'], $p['key'] );
				} else {
					update_post_meta( $p['id'], $p['key'], $p['value'] );
				}
				break;
			case 'option':
				if ( $this->blocked_option( $p['name'] ) ) {
					throw new Exception( 'blocked option' );
				}
				if ( empty( $p['existed'] ) ) {
					delete_option( $p['name'] );
				} else {
					update_option( $p['name'], $p['value'] );
				}
				break;
			case 'post_field':
				$res = wp_update_post( array( 'ID' => $p['id'], $p['field'] => $p['value'] ), true );
				if ( is_wp_error( $res ) ) {
					throw new Exception( 'post_field revert failed: ' . $res->get_error_message() );
				}
				break;
			case 'permalink':
				$uris = get_option( 'permalink-manager-uris' );
				if ( is_array( $uris ) ) {
					if ( empty( $p['existed'] ) ) {
						unset( $uris[ $p['post_id'] ] );
					} else {
						$uris[ $p['post_id'] ] = $p['value'];
					}
					update_option( 'permalink-manager-uris', $uris );
				}
				break;
			case 'post_create':
				if ( ! empty( $p['id'] ) ) {
					wp_trash_post( (int) $p['id'] ); // undo a create by trashing (recoverable)
				}
				break;

			case 'post_trash':
				// Undo a trash: untrash, then explicitly restore the captured prior status
				// (WP 5.6+ untrashes to 'draft', which would silently take a published page offline).
				wp_untrash_post( (int) $p['id'] );
				if ( ! empty( $p['status'] ) && get_post_status( (int) $p['id'] ) !== $p['status'] ) {
					$r = wp_update_post( array( 'ID' => (int) $p['id'], 'post_status' => $p['status'] ), true );
					if ( is_wp_error( $r ) ) {
						throw new Exception( 'post_trash revert failed: ' . $r->get_error_message() );
					}
				}
				break;
			case 'post_untrash':
				// Undo an untrash: re-trash (recoverable), preserving the original pre-trash status
				// so a later untrash restores it correctly.
				if ( ! $this->trash_enabled() ) {
					throw new Exception( 'cannot re-trash on revert: trash is disabled' );
				}
				wp_trash_post( (int) $p['id'] );
				if ( ! empty( $p['prev_status'] ) ) {
					update_post_meta( (int) $p['id'], '_wp_trash_meta_status', $p['prev_status'] );
				}
				break;
			case 'post_format':
				set_post_format( (int) $p['id'], ( empty( $p['value'] ) || 'standard' === $p['value'] ) ? false : $p['value'] );
				break;
			case 'sticky':
				if ( ! empty( $p['was_sticky'] ) ) {
					stick_post( (int) $p['id'] );
				} else {
					unstick_post( (int) $p['id'] );
				}
				break;

			case 'term_create':
				$r = wp_delete_term( (int) $p['term_id'], $p['taxonomy'] );
				if ( is_wp_error( $r ) ) {
					throw new Exception( 'term_create revert failed: ' . $r->get_error_message() );
				}
				break;
			case 'term_update':
				$r = wp_update_term( (int) $p['term_id'], $p['taxonomy'], array( 'name' => $p['name'], 'description' => $p['description'], 'parent' => (int) $p['parent'] ) );
				if ( is_wp_error( $r ) ) {
					throw new Exception( 'term_update revert failed: ' . $r->get_error_message() );
				}
				break;
			case 'term_relationship':
				$r = wp_set_object_terms( (int) $p['object_id'], array_map( 'intval', (array) $p['terms'] ), $p['taxonomy'], false );
				if ( is_wp_error( $r ) ) {
					throw new Exception( 'term_relationship revert failed: ' . $r->get_error_message() );
				}
				break;

			case 'options_set':
				foreach ( (array) $p['items'] as $it ) {
					$name = $it['name'];
					if ( $this->blocked_option( $name ) ) {
						continue;
					}
					if ( empty( $it['existed'] ) ) {
						delete_option( $name );
					} else {
						update_option( $name, $it['value'] );
					}
				}
				break;
			case 'theme_mod':
				$opt  = 'theme_mods_' . $p['theme'];
				$mods = get_option( $opt );
				if ( ! is_array( $mods ) ) {
					$mods = array();
				}
				if ( empty( $p['existed'] ) ) {
					unset( $mods[ $p['key'] ] );
				} else {
					$mods[ $p['key'] ] = $p['value'];
				}
				update_option( $opt, $mods );
				break;

			case 'nav_menu_create':
				$r = wp_delete_nav_menu( (int) $p['term_id'] );
				if ( is_wp_error( $r ) ) {
					throw new Exception( 'nav_menu_create revert failed: ' . $r->get_error_message() );
				}
				break;
			case 'nav_menu_rename':
				$r = wp_update_nav_menu_object( (int) $p['term_id'], array( 'menu-name' => $p['name'] ) );
				if ( is_wp_error( $r ) ) {
					throw new Exception( 'nav_menu_rename revert failed: ' . $r->get_error_message() );
				}
				break;
			case 'nav_menu_item':
				if ( 'nav_menu_item' === get_post_type( (int) $p['item_id'] ) ) {
					wp_delete_post( (int) $p['item_id'], true );
				}
				break;

			case 'attachment_fields':
				$b = $p['before'];
				$r = wp_update_post( array( 'ID' => (int) $p['id'], 'post_title' => $b['title'], 'post_excerpt' => $b['caption'], 'post_content' => $b['description'] ), true );
				if ( is_wp_error( $r ) ) {
					throw new Exception( 'attachment_fields revert failed: ' . $r->get_error_message() );
				}
				if ( empty( $b['alt_existed'] ) ) {
					delete_post_meta( (int) $p['id'], '_wp_attachment_image_alt' );
				} else {
					update_post_meta( (int) $p['id'], '_wp_attachment_image_alt', $b['alt'] );
				}
				break;
			case 'attachment_parent':
				wp_update_post( array( 'ID' => (int) $p['id'], 'post_parent' => (int) $p['prev_parent'] ) );
				if ( isset( $p['featured_post'] ) ) {
					if ( empty( $p['prev_thumb_existed'] ) ) {
						delete_post_meta( (int) $p['featured_post'], '_thumbnail_id' );
					} else {
						update_post_meta( (int) $p['featured_post'], '_thumbnail_id', $p['prev_thumb'] );
					}
				}
				break;

			case 'acf_field':
				if ( function_exists( 'update_field' ) ) {
					update_field( $p['key'], $p['value'], $p['post_id'] );
					if ( function_exists( 'acf_flush_value_cache' ) ) {
						acf_flush_value_cache( $p['post_id'], $p['key'] );
					}
				}
				break;

			case 'attachment_create':
				if ( isset( $p['featured_post'] ) ) {
					if ( empty( $p['prev_thumb_existed'] ) ) {
						delete_post_meta( (int) $p['featured_post'], '_thumbnail_id' );
					} else {
						update_post_meta( (int) $p['featured_post'], '_thumbnail_id', $p['prev_thumb'] );
					}
				}
				if ( ! empty( $p['id'] ) ) {
					wp_delete_attachment( (int) $p['id'], true );
				}
				break;

			case 'nav_menu_item_update':
				$r = wp_update_nav_menu_item( (int) $p['menu_id'], (int) $p['item_id'], $p['before'] );
				if ( is_wp_error( $r ) ) {
					throw new Exception( 'nav_menu_item_update revert failed: ' . $r->get_error_message() );
				}
				break;
			case 'nav_menu_item_recreate':
				$r = wp_update_nav_menu_item( (int) $p['menu_id'], 0, $p['before'] );
				if ( is_wp_error( $r ) ) {
					throw new Exception( 'nav_menu_item_recreate revert failed: ' . $r->get_error_message() );
				}
				break;
			case 'nav_menu_order':
				foreach ( (array) $p['items'] as $iid => $ord ) {
					wp_update_post( array( 'ID' => (int) $iid, 'menu_order' => (int) $ord ) );
				}
				break;
			case 'nav_menu_locations':
				set_theme_mod( 'nav_menu_locations', (array) $p['value'] );
				break;
			case 'plugin_state':
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
				if ( isset( $p['plugin'] ) && $p['plugin'] === plugin_basename( __FILE__ ) ) {
					throw new Exception( 'refusing to deactivate/alter JB Ops itself on revert' );
				}
				$nw = ! empty( $p['network'] );
				if ( 'activated' === $p['action'] ) {
					deactivate_plugins( $p['plugin'], false, $nw );
				} else {
					$this->safe_activate_plugin( $p['plugin'], $nw );
				}
				break;
			case 'file':
				$norm = $this->fs_norm_abs( (string) ( $p['path'] ?? '' ) );
				$wc   = realpath( WP_CONTENT_DIR );
				// Re-assert the full write scope + blocklist at restore time (defends a tampered
				// payload, and mirrors fs_resolve_write: themes/plugins only, never the JB Ops dir).
				if ( ! $wc || ( ! $this->path_under( $norm, $wc . DIRECTORY_SEPARATOR . 'themes' )
					&& ! $this->path_under( $norm, $wc . DIRECTORY_SEPARATOR . 'plugins' ) ) ) {
					throw new Exception( 'file revert refused: path outside themes/plugins' );
				}
				$self = realpath( plugin_dir_path( __FILE__ ) );
				if ( $self && $this->path_under( $norm, $self ) ) {
					throw new Exception( 'file revert refused: JB Ops plugin directory' );
				}
				if ( $this->fs_blocked_file( $norm ) ) {
					throw new Exception( 'file revert refused: blocked path' );
				}
				if ( empty( $p['existed'] ) ) {
					// File was newly created -> delete it to undo.
					if ( is_file( $norm ) && ! @unlink( $norm ) ) {
						throw new Exception( 'file revert failed: could not delete created file' );
					}
				} elseif ( false === file_put_contents( $norm, (string) $p['before'], LOCK_EX ) ) {
					throw new Exception( 'file revert failed: could not restore prior content' );
				}
				if ( function_exists( 'opcache_invalidate' ) ) {
					@opcache_invalidate( $norm, true );
				}
				break;
			case 'export_file':
				// "Undo" a DB export = delete the generated dump (+ its manifest) early, before the
				// 1h TTL or first download would. Re-assert the path is inside the export dir so a
				// tampered payload can't delete arbitrary files.
				$dir = $this->export_dir();
				foreach ( array( $p['path'] ?? '', $p['meta'] ?? '' ) as $f ) {
					$f = (string) $f;
					if ( '' !== $f && $this->path_under( $f, $dir ) && is_file( $f ) ) {
						@unlink( $f );
					}
				}
				break;
			default:
				throw new Exception( 'unknown revert type' );
		}
	}

	/* ----- confirm-token (dry-run gate) + revert-token storage ----- */

	private function args_hash( $op, $args ) {
		return md5( wp_json_encode( array( $op, $args ) ) );
	}
	private function store_confirm( $op, $args ) {
		$token = bin2hex( random_bytes( 16 ) );
		set_transient( 'h_ops_cf_' . $token, array( 'op' => $op, 'h' => $this->args_hash( $op, $args ) ), self::CONFIRM_TTL );
		return $token;
	}
	/** @return true|string  true if valid, else an error message. Single-use. */
	private function check_confirm( $token, $op, $args ) {
		if ( '' === $token ) {
			return 'A confirm_token from a prior dry run is required to apply.';
		}
		$rec = get_transient( 'h_ops_cf_' . $token );
		if ( ! is_array( $rec ) ) {
			return 'confirm_token invalid or expired — run the dry run again.';
		}
		if ( ( $rec['op'] ?? '' ) !== $op || ( $rec['h'] ?? '' ) !== $this->args_hash( $op, $args ) ) {
			return 'confirm_token does not match this op/args — re-run the dry run for the exact change.';
		}
		delete_transient( 'h_ops_cf_' . $token ); // single use
		return true;
	}
	private function revert_table() {
		global $wpdb;
		$t = $wpdb->prefix . 'h_ops_revert';
		return ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $t ) ) === $t ) ? $t : '';
	}
	/**
	 * Persist a revert payload to a DURABLE table (survives object-cache eviction, unlike the old
	 * 24h transient), returning a single-use token. Falls back to a transient only if the table is
	 * missing. The payload holds real before-values needed to restore, so this table is as
	 * sensitive as wp_options and is never exposed by a read op.
	 */
	private function store_revert( $payload, $op = '' ) {
		$token = bin2hex( random_bytes( 16 ) );
		$table = $this->revert_table();
		if ( '' === $table ) {
			set_transient( 'h_ops_rv_' . $token, $payload, self::REVERT_TTL );
			return $token;
		}
		global $wpdb;
		$now = time();
		$wpdb->insert( $table, array(
			'token'   => $token,
			'op'      => (string) $op,
			'payload' => wp_json_encode( $payload ),
			'created' => gmdate( 'Y-m-d H:i:s', $now ),
			'expires' => gmdate( 'Y-m-d H:i:s', $now + self::REVERT_TTL ),
			'used'    => 0,
		) );
		// Opportunistic prune of consumed/expired rows.
		$wpdb->query( $wpdb->prepare( "DELETE FROM $table WHERE used = 1 OR expires < %s", gmdate( 'Y-m-d H:i:s', $now ) ) );
		return $token;
	}

	/** Strip the internal revert payload before returning a diff to the client. */
	private function public_diff( $preview ) {
		return array(
			'before'       => $preview['before'] ?? null,
			'after'        => $preview['after'] ?? null,
			'would_change' => ! empty( $preview['would_change'] ),
			'summary'      => $preview['summary'] ?? '',
		);
	}

	/* ---------------------------------------------------------------------
	 * Helpers
	 * ------------------------------------------------------------------- */

	/** Redact values whose key looks secret. Recurses into arrays. */
	private function redact( $key, $value ) {
		$pattern = '/(pass|secret|token|api[_-]?key|\bkey\b|salt|nonce|smtp|stripe|auth|private|credential|license)/i';
		if ( is_string( $key ) && preg_match( $pattern, $key ) ) {
			return '[REDACTED]';
		}
		if ( is_array( $value ) ) {
			$out = array();
			foreach ( $value as $k => $v ) {
				$out[ $k ] = $this->redact( (string) $k, $v );
			}
			return $out;
		}
		// Also redact values that LOOK like a secret regardless of key name (JWT/PEM/AWS/
		// high-entropy tokens). Reads previously only matched key names, leaking secrets
		// stored under generic keys; this brings read-time redaction up to audit_scrub's level.
		return $this->looks_secret( $value ) ? '[REDACTED]' : $value;
	}

	/** Prevent dumping multi-MB option blobs over the wire. */
	private function cap_size( $value ) {
		$json = wp_json_encode( $value );
		if ( is_string( $json ) && strlen( $json ) > 50000 ) {
			return array( '_truncated' => true, '_bytes' => strlen( $json ), 'preview' => substr( $json, 0, 2000 ) );
		}
		return $value;
	}

	/** Heuristic: does this scalar look like a credential/secret regardless of its key name? */
	private function looks_secret( $v ) {
		if ( ! is_string( $v ) || strlen( $v ) < 16 ) {
			return false;
		}
		if ( false !== strpos( $v, '-----BEGIN' ) ) {
			return true; // PEM private key / cert block
		}
		// JWT / Stripe / AWS / GitHub / Slack token shapes.
		if ( preg_match( '#(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}|sk_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|gh[posru]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})#', $v ) ) {
			return true;
		}
		// Long single-token high-entropy string (hex/base64), no whitespace — looks like a raw key/token.
		if ( strlen( $v ) >= 40 && preg_match( '/^[A-Za-z0-9+\/=_-]+$/', $v ) ) {
			return true;
		}
		return false;
	}

	/** Stronger scrub for data persisted AT REST in the audit log: key-pattern redact + value heuristic. */
	private function audit_scrub( $value, $key = '' ) {
		$pattern = '/(pass|secret|token|api[_-]?key|\bkey\b|salt|nonce|smtp|stripe|auth|private|credential|license)/i';
		if ( is_string( $key ) && preg_match( $pattern, $key ) ) {
			return '[REDACTED]';
		}
		if ( is_array( $value ) ) {
			$out = array();
			foreach ( $value as $k => $v ) {
				$out[ $k ] = $this->audit_scrub( $v, (string) $k );
			}
			return $out;
		}
		return $this->looks_secret( $value ) ? '[REDACTED]' : $value;
	}

	/**
	 * Caller IP. Defaults to REMOTE_ADDR (the only non-spoofable source). Caller-supplied
	 * forwarding headers are trusted ONLY when the operator has confirmed this site sits behind
	 * a proxy/CDN that overwrites them (trust_proxy setting) — otherwise they are forgeable and
	 * would both defeat the IP allowlist and poison the audit trail.
	 */
	private function client_ip() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$s = $this->settings();
		if ( empty( $s['trust_proxy'] ) ) {
			return $remote;
		}
		foreach ( array( 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR' ) as $k ) {
			if ( ! empty( $_SERVER[ $k ] ) ) {
				$first = trim( explode( ',', (string) wp_unslash( $_SERVER[ $k ] ) )[0] );
				if ( '' !== $first ) {
					return sanitize_text_field( $first );
				}
			}
		}
		return $remote;
	}

	private function audit( $op, $args, $status, $extra = array() ) {
		global $wpdb;
		$table = $this->log_table();
		if ( '' === $table ) {
			return 0;
		}
		// Never persist raw secrets at rest: value-aware scrub (key pattern + secret-shaped values) + size cap.
		$wpdb->insert( $table, array(
			'ts'     => current_time( 'mysql' ),
			'ip'     => $this->client_ip(),
			'op'     => $op,
			'args'   => wp_json_encode( $this->cap_size( $this->audit_scrub( $args ) ) ),
			'status' => $status,
			'meta'   => wp_json_encode( $this->cap_size( $this->audit_scrub( $extra ) ) ),
		) );
		return (int) $wpdb->insert_id;
	}

	private function ok( $op, $data, $meta = array(), $dry_run = null ) {
		return new WP_REST_Response( array(
			'ok'      => true,
			'op'      => $op,
			'dry_run' => $dry_run,
			'data'    => $data,
			'meta'    => $meta,
		), 200 );
	}

	private function fail( $op, $code, $message, $status = 400 ) {
		return new WP_REST_Response( array(
			'ok'      => false,
			'op'      => $op,
			'error'   => $code,
			'message' => $message,
		), $status );
	}

	/* ---------------------------------------------------------------------
	 * Admin settings page (all config lives here — no env/constants needed)
	 * ------------------------------------------------------------------- */

	public function admin_menu() {
		if ( ! $this->admin_allowed() ) {
			return; // hide the menu entirely from non-administrators
		}
		add_menu_page( 'JB Ops Bridge', 'JB Ops', 'manage_options', 'h-ops', array( $this, 'render_dashboard' ), 'dashicons-rest-api', 80 );
		add_submenu_page( 'h-ops', 'JB Ops — Activity', 'Dashboard', 'manage_options', 'h-ops', array( $this, 'render_dashboard' ) );
		add_submenu_page( 'h-ops', 'JB Ops — Settings', 'Settings', 'manage_options', 'h-ops-settings', array( $this, 'render_settings' ) );
	}

	public function handle_admin_save() {
		if ( ! $this->admin_allowed() ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'h_ops_save' );

		$s = $this->settings();
		$s['enabled']        = ! empty( $_POST['h_ops_enabled'] );
		$s['writes_enabled'] = ! empty( $_POST['h_ops_writes_enabled'] );
		$s['allow_danger']   = ! empty( $_POST['h_ops_allow_danger'] );
		$s['export_enabled'] = ! empty( $_POST['h_ops_export_enabled'] );
		$s['ip_allowlist']   = isset( $_POST['h_ops_ip_allowlist'] ) ? sanitize_textarea_field( wp_unslash( $_POST['h_ops_ip_allowlist'] ) ) : '';
		$s['trust_proxy']    = ! empty( $_POST['h_ops_trust_proxy'] );
		$s['rate_limit']     = isset( $_POST['h_ops_rate_limit'] ) ? absint( $_POST['h_ops_rate_limit'] ) : 0;
		$raw_allow           = isset( $_POST['h_ops_allowed_ops'] ) ? (string) wp_unslash( $_POST['h_ops_allowed_ops'] ) : '';
		$allow_list          = array_filter( array_map( 'sanitize_key', preg_split( '/[\s,]+/', $raw_allow ) ) );
		$s['allowed_ops']    = array_values( array_unique( $allow_list ) );

		// Generate a token on first enable, or when explicitly regenerated.
		if ( empty( $s['token'] ) || ! empty( $_POST['h_ops_regenerate'] ) ) {
			$s['token'] = bin2hex( random_bytes( 24 ) ); // 48 hex chars
		}
		// Bind the settings to this site so a DB sync to another site won't stay enabled.
		$s['site'] = home_url();

		update_option( 'h_ops_settings', $s );

		wp_safe_redirect( add_query_arg( array( 'page' => 'h-ops-settings', 'updated' => 1 ), admin_url( 'admin.php' ) ) );
		exit;
	}

	public function handle_clear_log() {
		if ( ! $this->admin_allowed() ) {
			wp_die( 'Insufficient permissions.' );
		}
		check_admin_referer( 'h_ops_clear_log' );
		global $wpdb;
		$table = $wpdb->prefix . 'h_ops_log';
		if ( $wpdb->get_var( "SHOW TABLES LIKE '$table'" ) === $table ) {
			$wpdb->query( "TRUNCATE TABLE $table" );
		}
		wp_safe_redirect( add_query_arg( array( 'page' => 'h-ops', 'cleared' => 1 ), admin_url( 'admin.php' ) ) );
		exit;
	}

	public function render_settings() {
		if ( ! $this->admin_allowed() ) {
			wp_die( 'You do not have access to JB Ops Bridge.' );
		}
		$s            = $this->settings();
		$enabled      = ! empty( $s['enabled'] );
		$writes       = ! empty( $s['writes_enabled'] );
		$allow_danger = ! empty( $s['allow_danger'] );
		$export       = ! empty( $s['export_enabled'] );
		$allowed_ops  = ( isset( $s['allowed_ops'] ) && is_array( $s['allowed_ops'] ) ) ? implode( ', ', $s['allowed_ops'] ) : '';
		$ip_allowlist = isset( $s['ip_allowlist'] ) ? (string) $s['ip_allowlist'] : '';
		$trust_proxy  = ! empty( $s['trust_proxy'] );
		$rate_limit   = isset( $s['rate_limit'] ) ? (int) $s['rate_limit'] : 0;
		$token        = isset( $s['token'] ) ? $s['token'] : '';
		$base         = home_url( '/wp-json/' . H_OPS_NS );
		$mismatch     = $this->site_mismatch();
		?>
		<div class="wrap">
			<h1>JB Ops Bridge</h1>
			<p>Secured REST endpoint for AI-assisted site/DB inspection and controlled changes (writes are opt-in, dry-run by default). All configuration lives here — no <code>wp-config</code> or <code>.env</code> changes needed.</p>

			<?php if ( ! empty( $_GET['updated'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p>Settings saved.</p></div>
			<?php endif; ?>

			<?php if ( $mismatch ) : ?>
				<div class="notice notice-warning"><p><strong>Disabled by site-binding.</strong> These settings were enabled for
				<code><?php echo esc_html( $s['site'] ); ?></code> but this site is <code><?php echo esc_html( home_url() ); ?></code>
				(looks like a DB copy). Re-save below to enable here.</p></div>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">
				<input type="hidden" name="action" value="h_ops_save" />
				<?php wp_nonce_field( 'h_ops_save' ); ?>
				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">Status</th>
						<td>
							<label><input type="checkbox" name="h_ops_enabled" value="1" <?php checked( $enabled ); ?> /> Enable the endpoint</label>
							<p class="description">Off by default. While off, every request returns 403.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Write operations</th>
						<td>
							<label><input type="checkbox" name="h_ops_writes_enabled" value="1" <?php checked( $writes ); ?> /> Allow write operations</label>
							<p class="description">Separate, deliberate switch. Reads always work when enabled; writes only when this is on.
							Every write is <strong>dry-run by default</strong> (returns a before/after diff + a one-time <code>confirm_token</code>); applying needs that token, and each applied write returns a <code>revert_token</code>.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Danger operations</th>
						<td>
							<label><input type="checkbox" name="h_ops_allow_danger" value="1" <?php checked( $allow_danger ); ?> /> Allow danger-tier operations</label>
							<p class="description">Off by default. Danger-tier ops (e.g. plugin/theme lifecycle, deletes) <strong>also</strong> require each op to be named in the per-op allowlist below. Leave off unless you are deliberately running one.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Database export</th>
						<td>
							<label><input type="checkbox" name="h_ops_export_enabled" value="1" <?php checked( $export ); ?> /> Allow database export</label>
							<p class="description">Off by default. Enables the <code>export_db</code> op (gzipped SQL dump for standing up a local copy). This is a danger-tier op, so it <strong>also</strong> needs the danger toggle above <em>and</em> <code>export_db</code> in the per-op allowlist. ⚠️ A full dump includes password hashes, API keys and PII <strong>with no redaction</strong> — only turn this on for a deliberate migration. The download is one-time, bearer-gated, and expires in 1 hour.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Per-op allowlist</th>
						<td>
							<textarea name="h_ops_allowed_ops" rows="3" class="large-text code" placeholder="Leave blank to allow all enabled-tier ops. e.g. trash_post, set_featured_image"><?php echo esc_textarea( $allowed_ops ); ?></textarea>
							<p class="description">Optional. When <strong>non-empty</strong>, ONLY the listed ops may run (comma / space / newline separated). Danger-tier ops must always be listed here to run.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">IP allowlist</th>
						<td>
							<textarea name="h_ops_ip_allowlist" rows="2" class="large-text code" placeholder="Leave blank to allow any IP. e.g. 203.0.113.7, 10.0.0.0/24"><?php echo esc_textarea( $ip_allowlist ); ?></textarea>
							<p class="description">Optional. When set, write requests are refused unless the caller IP matches (exact IP or IPv4 CIDR). Matched against <code>REMOTE_ADDR</code> by default.</p>
							<label><input type="checkbox" name="h_ops_trust_proxy" value="1" <?php checked( $trust_proxy ); ?> /> Trust proxy headers (<code>CF-Connecting-IP</code> / <code>X-Forwarded-For</code>)</label>
							<p class="description">Enable ONLY if this site sits behind a proxy/CDN (e.g. Cloudflare) that overwrites these headers — otherwise they are caller-spoofable and would defeat the allowlist and poison the audit log.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Write rate limit</th>
						<td>
							<input type="number" name="h_ops_rate_limit" min="0" step="1" value="<?php echo esc_attr( $rate_limit ); ?>" class="small-text" /> write attempts / minute
							<p class="description">Optional, best-effort throttle (counts dry-runs as well as applies, per token). <code>0</code> = off.</p>
						</td>
					</tr>
					<tr>
						<th scope="row">Access token</th>
						<td>
							<?php if ( $token ) : ?>
								<input type="text" readonly class="regular-text code" style="width:30rem" value="<?php echo esc_attr( $token ); ?>" onclick="this.select()" />
								<p class="description">Send as <code>Authorization: Bearer &lt;token&gt;</code>. <label><input type="checkbox" name="h_ops_regenerate" value="1" /> Regenerate on save</label></p>
							<?php else : ?>
								<em>A token will be generated when you enable and save.</em>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row">Endpoint</th>
						<td><code><?php echo esc_html( $base ); ?></code>
							<p class="description">Health check: <code><?php echo esc_html( $base . '/ping' ); ?></code> &middot; Operations: <code>/ops</code> &middot; Run: <code>POST /run</code></p>
						</td>
					</tr>
				</table>
				<?php submit_button( 'Save settings' ); ?>
			</form>

			<h2>Quick test</h2>
			<pre class="code" style="background:#fff;border:1px solid #dcdcde;padding:12px;overflow:auto;">curl -s -H "Authorization: Bearer <?php echo esc_html( $token ? $token : '&lt;TOKEN&gt;' ); ?>" <?php echo esc_html( $base ); ?>/ping</pre>

			<p class="description">⚠️ The token is stored in the database. This site uses DB sync tools — the site-binding guard above prevents an enabled state from following a DB copy to another environment, but treat the token like a password and regenerate if a DB is shared.</p>

			<p><a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=h-ops' ) ); ?>">View activity dashboard &rarr;</a></p>
		</div>
		<?php
	}

	/* ---------------------------------------------------------------------
	 * Activity dashboard
	 * ------------------------------------------------------------------- */

	private function log_table() {
		global $wpdb;
		$table = $wpdb->prefix . 'h_ops_log';
		return ( $wpdb->get_var( "SHOW TABLES LIKE '$table'" ) === $table ) ? $table : '';
	}

	private function log_stats( $table ) {
		global $wpdb;
		$cutoff = gmdate( 'Y-m-d H:i:s', current_time( 'timestamp' ) - DAY_IN_SECONDS );
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT COUNT(*) AS total,
				SUM(status='ok') AS `reads`,
				SUM(status='dry_run') AS dry_runs,
				SUM(status='applied') AS applied,
				SUM(status='reverted') AS reverted,
				SUM(status='error') AS errors,
				SUM(ts >= %s) AS last24h,
				MAX(ts) AS last_ts
			FROM $table",
			$cutoff
		), ARRAY_A );
		return $row ?: array();
	}

	public function render_dashboard() {
		if ( ! $this->admin_allowed() ) {
			wp_die( 'You do not have access to JB Ops Bridge.' );
		}
		global $wpdb;
		$enabled = $this->is_enabled();
		$writes  = $this->writes_enabled();
		$table   = $this->log_table();

		// Filters + pagination
		$f_op     = isset( $_GET['op'] ) ? sanitize_key( $_GET['op'] ) : '';
		$f_status = isset( $_GET['status'] ) ? sanitize_key( $_GET['status'] ) : '';
		$f_search = isset( $_GET['s'] ) ? sanitize_text_field( wp_unslash( $_GET['s'] ) ) : '';
		$paged    = isset( $_GET['paged'] ) ? max( 1, absint( $_GET['paged'] ) ) : 1;
		$per_page = 50;
		?>
		<div class="wrap">
			<h1>JB Ops Bridge — Activity</h1>

			<?php if ( ! empty( $_GET['cleared'] ) ) : ?>
				<div class="notice notice-success is-dismissible"><p>Activity log cleared.</p></div>
			<?php endif; ?>

			<p>
				Status:
				<strong style="color:<?php echo $enabled ? '#008a20' : '#b32d2e'; ?>"><?php echo $enabled ? 'Enabled' : 'Disabled'; ?></strong>
				&middot; Writes: <strong style="color:<?php echo $writes ? '#b32d2e' : '#646970'; ?>"><?php echo $writes ? 'On' : 'Off'; ?></strong>
				&middot; <a href="<?php echo esc_url( admin_url( 'admin.php?page=h-ops-settings' ) ); ?>">Settings</a>
			</p>

			<?php
			if ( ! $table ) {
				echo '<div class="notice notice-warning"><p>No audit table found. Deactivate &amp; reactivate the plugin to create it.</p></div></div>';
				return;
			}
			$stats = $this->log_stats( $table );
			$last  = ! empty( $stats['last_ts'] ) ? sprintf( '%s ago', human_time_diff( strtotime( $stats['last_ts'] ), current_time( 'timestamp' ) ) ) : '—';
			$cards = array(
				array( 'Total calls', (int) ( $stats['total'] ?? 0 ), '#1d2327' ),
				array( 'Last 24h', (int) ( $stats['last24h'] ?? 0 ), '#1d2327' ),
				array( 'Reads', (int) ( $stats['reads'] ?? 0 ), '#2271b1' ),
				array( 'Dry runs', (int) ( $stats['dry_runs'] ?? 0 ), '#996800' ),
				array( 'Applied', (int) ( $stats['applied'] ?? 0 ), '#b32d2e' ),
				array( 'Reverted', (int) ( $stats['reverted'] ?? 0 ), '#b32d2e' ),
				array( 'Errors', (int) ( $stats['errors'] ?? 0 ), '#b32d2e' ),
			);
			?>
			<div style="display:flex;gap:12px;flex-wrap:wrap;margin:16px 0;">
				<?php foreach ( $cards as $c ) : ?>
					<div style="background:#fff;border:1px solid #c3c4c7;border-radius:6px;padding:12px 18px;min-width:96px;">
						<div style="font-size:12px;color:#646970;text-transform:uppercase;letter-spacing:.04em;"><?php echo esc_html( $c[0] ); ?></div>
						<div style="font-size:26px;font-weight:600;color:<?php echo esc_attr( $c[2] ); ?>;"><?php echo esc_html( $c[1] ); ?></div>
					</div>
				<?php endforeach; ?>
				<div style="background:#fff;border:1px solid #c3c4c7;border-radius:6px;padding:12px 18px;min-width:140px;">
					<div style="font-size:12px;color:#646970;text-transform:uppercase;letter-spacing:.04em;">Last activity</div>
					<div style="font-size:18px;font-weight:600;"><?php echo esc_html( $last ); ?></div>
				</div>
			</div>

			<?php // Filter bar
			$ops_for_filter = $wpdb->get_col( "SELECT DISTINCT op FROM $table ORDER BY op" );
			$statuses       = array( 'ok', 'dry_run', 'applied', 'reverted', 'error' );
			?>
			<form method="get" style="margin:12px 0;">
				<input type="hidden" name="page" value="h-ops" />
				<select name="op">
					<option value="">All ops</option>
					<?php foreach ( $ops_for_filter as $o ) : ?>
						<option value="<?php echo esc_attr( $o ); ?>" <?php selected( $f_op, $o ); ?>><?php echo esc_html( $o ); ?></option>
					<?php endforeach; ?>
				</select>
				<select name="status">
					<option value="">All statuses</option>
					<?php foreach ( $statuses as $st ) : ?>
						<option value="<?php echo esc_attr( $st ); ?>" <?php selected( $f_status, $st ); ?>><?php echo esc_html( $st ); ?></option>
					<?php endforeach; ?>
				</select>
				<input type="search" name="s" value="<?php echo esc_attr( $f_search ); ?>" placeholder="Search args…" />
				<button class="button">Filter</button>
				<?php if ( $f_op || $f_status || $f_search ) : ?>
					<a class="button-link" href="<?php echo esc_url( admin_url( 'admin.php?page=h-ops' ) ); ?>">Reset</a>
				<?php endif; ?>
			</form>

			<?php
			// Build WHERE
			$where = array( '1=1' );
			$params = array();
			if ( $f_op )     { $where[] = 'op = %s';     $params[] = $f_op; }
			if ( $f_status ) { $where[] = 'status = %s'; $params[] = $f_status; }
			if ( '' !== $f_search ) { $where[] = 'args LIKE %s'; $params[] = '%' . $wpdb->esc_like( $f_search ) . '%'; }
			$where_sql = implode( ' AND ', $where );

			$total_rows = (int) ( $params
				? $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $table WHERE $where_sql", $params ) )
				: $wpdb->get_var( "SELECT COUNT(*) FROM $table WHERE $where_sql" ) );
			$pages  = max( 1, (int) ceil( $total_rows / $per_page ) );
			$paged  = min( $paged, $pages );
			$offset = ( $paged - 1 ) * $per_page;

			$q = "SELECT id, ts, ip, op, status, args, meta FROM $table WHERE $where_sql ORDER BY id DESC LIMIT %d OFFSET %d";
			$rows = $wpdb->get_results( $wpdb->prepare( $q, array_merge( $params, array( $per_page, $offset ) ) ) );
			?>

			<table class="widefat striped">
				<thead><tr>
					<th style="width:150px;">When</th><th style="width:120px;">IP</th>
					<th>Op</th><th style="width:90px;">Status</th><th>Detail</th><th style="width:90px;">Data</th>
				</tr></thead>
				<tbody>
				<?php if ( ! $rows ) : ?>
					<tr><td colspan="6"><em>No matching activity.</em></td></tr>
				<?php else : foreach ( $rows as $r ) :
					$meta   = json_decode( (string) $r->meta, true );
					$detail = is_array( $meta ) && isset( $meta['summary'] ) && '' !== $meta['summary'] ? $meta['summary']
						: ( is_array( $meta ) && isset( $meta['message'] ) ? $meta['message']
						: ( is_array( $meta ) && isset( $meta['took_ms'] ) ? $meta['took_ms'] . 'ms' : '' ) );
					$color  = in_array( $r->status, array( 'applied', 'reverted', 'error' ), true ) ? '#b32d2e' : ( 'dry_run' === $r->status ? '#996800' : '#646970' );
					$ago    = human_time_diff( strtotime( $r->ts ), current_time( 'timestamp' ) );
					?>
					<tr>
						<td title="<?php echo esc_attr( $r->ts ); ?>"><?php echo esc_html( $r->ts ); ?><br><span style="color:#646970;font-size:11px;"><?php echo esc_html( $ago ); ?> ago</span></td>
						<td><?php echo esc_html( $r->ip ?: '-' ); ?></td>
						<td><code><?php echo esc_html( $r->op ); ?></code></td>
						<td><span style="color:<?php echo esc_attr( $color ); ?>;font-weight:600;"><?php echo esc_html( $r->status ); ?></span></td>
						<td><?php echo esc_html( $detail ); ?></td>
						<td><details><summary style="cursor:pointer;">view</summary>
							<pre style="white-space:pre-wrap;font-size:11px;background:#f6f7f7;padding:8px;border-radius:4px;max-width:520px;overflow:auto;">args: <?php echo esc_html( $this->pretty( $r->args ) ); ?>

meta: <?php echo esc_html( $this->pretty( $r->meta ) ); ?></pre>
						</details></td>
					</tr>
				<?php endforeach; endif; ?>
				</tbody>
			</table>

			<?php if ( $pages > 1 ) :
				$base = add_query_arg( array_filter( array( 'page' => 'h-ops', 'op' => $f_op, 'status' => $f_status, 's' => $f_search ) ), admin_url( 'admin.php' ) );
				?>
				<p style="margin-top:12px;">
					<?php for ( $i = 1; $i <= $pages; $i++ ) :
						$url = add_query_arg( 'paged', $i, $base ); ?>
						<?php if ( $i === $paged ) : ?>
							<strong style="padding:2px 8px;"><?php echo (int) $i; ?></strong>
						<?php else : ?>
							<a href="<?php echo esc_url( $url ); ?>" style="padding:2px 8px;"><?php echo (int) $i; ?></a>
						<?php endif; ?>
					<?php endfor; ?>
					<span style="color:#646970;">(<?php echo (int) $total_rows; ?> entries)</span>
				</p>
			<?php endif; ?>

			<form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top:18px;"
				onsubmit="return confirm('Clear the entire activity log? This cannot be undone.');">
				<input type="hidden" name="action" value="h_ops_clear_log" />
				<?php wp_nonce_field( 'h_ops_clear_log' ); ?>
				<button class="button button-link-delete">Clear activity log</button>
			</form>
		</div>
		<?php
	}

	private function pretty( $json ) {
		$d = json_decode( (string) $json, true );
		return null === $d ? (string) $json : wp_json_encode( $d, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
	}

	/* ---------------------------------------------------------------------
	 * Activation: audit table
	 * ------------------------------------------------------------------- */

	public static function activate() {
		self::create_tables();
		update_option( 'h_ops_db_version', H_OPS_VERSION, false );
	}

	/**
	 * Create/upgrade the plugin tables. Idempotent (dbDelta), so it is safe to re-run on every
	 * version bump. Column types are lowercased and PRIMARY KEY uses two spaces to satisfy the
	 * dbDelta contract (so re-runs don't throw "Multiple primary key defined").
	 */
	private static function create_tables() {
		global $wpdb;
		$charset = $wpdb->get_charset_collate();
		$log     = $wpdb->prefix . 'h_ops_log';
		$revert  = $wpdb->prefix . 'h_ops_revert';

		$sql_log = "CREATE TABLE $log (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ts datetime NOT NULL,
			ip varchar(64) NOT NULL DEFAULT '',
			op varchar(64) NOT NULL DEFAULT '',
			args longtext NULL,
			status varchar(16) NOT NULL DEFAULT '',
			meta text NULL,
			PRIMARY KEY  (id),
			KEY ts (ts)
		) $charset;";

		// Durable revert store: undo payloads live here (not volatile transients) so an applied
		// change stays revertible for REVERT_TTL even under object-cache eviction.
		$sql_revert = "CREATE TABLE $revert (
			token char(32) NOT NULL,
			op varchar(64) NOT NULL DEFAULT '',
			payload longtext NULL,
			created datetime NOT NULL,
			expires datetime NOT NULL,
			used tinyint(1) NOT NULL DEFAULT 0,
			PRIMARY KEY  (token),
			KEY expires (expires)
		) $charset;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql_log );
		dbDelta( $sql_revert );
	}

	/**
	 * Runs on plugins_loaded: when the file version moves ahead of the recorded DB version (e.g. an
	 * in-place deploy that never fires the activation hook), (re)create the tables in place so the
	 * durable revert store never silently degrades to volatile transients.
	 */
	public function maybe_upgrade() {
		if ( get_option( 'h_ops_db_version' ) === H_OPS_VERSION ) {
			return;
		}
		self::create_tables();
		update_option( 'h_ops_db_version', H_OPS_VERSION, false );
	}
}

register_activation_hook( __FILE__, array( 'H_Ops_Bridge', 'activate' ) );

new H_Ops_Bridge();
