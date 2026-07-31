<?php
/**
 * Plugin Name: JB Site Health
 * Description: Read-only site-health endpoint for the Juicebox Digital Support Plan report. Returns the data points that cannot be observed from outside the site — WordPress/PHP version, plugin update status, hardening flags, and brute-force counts.
 * Version:     1.3.0
 * Author:      Juicebox Creative
 * License:     Proprietary — internal Juicebox use only
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS
 * ---------------------------------------------------------------------------
 * The Digital Support Plan report runs ~29 checks. 23 are observable from
 * outside the site (SSL/TLS, HTTP headers, DNS, indexability, uptime). Six are
 * not, and today they render as "Unknown" or "Needs access to check":
 *
 *   1. WordPress version          4. PHP execution in the uploads directory
 *   2. PHP version                5. Plugin update status
 *   3. DISALLOW_FILE_EDIT         6. Brute-force attempt counts
 *
 * This plugin closes all six over a single authenticated request.
 *
 * ---------------------------------------------------------------------------
 * WHY A DEDICATED PLUGIN, NOT THE jb-ops BRIDGE
 * ---------------------------------------------------------------------------
 * jb-ops can already answer some of this, but it carries 80+ operations
 * including write_file / export_db / update_option / activate_plugin. Shipping
 * that to every client site purely to feed a monthly read-only report is far
 * more privilege than the job needs. This plugin is READ-ONLY BY CONSTRUCTION:
 * there is no code path here that writes to the database, the filesystem, or
 * the options table. If its key leaks the worst case is information
 * disclosure, not site takeover — so it carries its OWN keypair, deliberately
 * separate from the jb-ops fleet key.
 *
 * ---------------------------------------------------------------------------
 * INSTALLATION — two options, no per-site configuration either way
 * ---------------------------------------------------------------------------
 *   a) Drop this single file into wp-content/mu-plugins/ (or app/mu-plugins/
 *      on Bedrock). It auto-activates. Being a FLAT file, it needs no loader
 *      stub — mu-plugins does not autoload subdirectories.
 *   b) Or install it as a normal plugin and activate it.
 *
 * ---------------------------------------------------------------------------
 * THE ONE RULE: NEVER GUESS
 * ---------------------------------------------------------------------------
 * The report is client-facing, so a wrong value is worse than an honest "don't
 * know". Every field that cannot be determined returns null together with a
 * `reason` string. Nothing here infers, rounds, or falls back to a plausible
 * default.
 *
 * @package JB_Site_Health
 */

defined( 'ABSPATH' ) || exit;

/**
 * A site can legitimately end up holding this file twice — most often mid-
 * migration, when the flat mu-plugin copy is still in place and Composer has
 * just installed the packaged version alongside it under
 * mu-plugins/juicebox-site-health/. WordPress includes both, and the duplicate
 * class declaration would fatal the whole site. Whichever copy loads second
 * bows out quietly instead.
 */
if ( defined( 'JB_HEALTH_VERSION' ) ) {
	return;
}

/**
 * Fleet signing public keys. A public key can VERIFY a token but never FORGE
 * one, so shipping them to every site is safe — the private half lives only in
 * the private skills repo, next to the caller that signs with it. Deliberately
 * NOT the jb-ops key: separate credential, separate blast radius.
 *
 * This is a LIST, not a single key, and that is the point: rotation would
 * otherwise mean swapping the key on ~40 sites in the same instant or locking
 * ourselves out. Instead, add the incoming key here and deploy the fleet at
 * whatever pace suits; both keys verify meanwhile. Once every site is carrying
 * it, switch the caller over and drop the retired key on the next routine
 * deploy. Newest first — the common case then matches on the first pass.
 *
 * Defining JB_HEALTH_SIGNING_PUBKEYS in wp-config.php overrides the list
 * entirely, which is how a one-off site opts out of the fleet credential.
 */
if ( ! defined( 'JB_HEALTH_SIGNING_PUBKEYS' ) ) {
	define(
		'JB_HEALTH_SIGNING_PUBKEYS',
		array(
			'1bqkgVQVjVQmovyhqMrS7qqKk8A7NKf3ablhA4icVtA=',
		)
	);
}
define( 'JB_HEALTH_SIGN_CONTEXT', 'jb-health-v1:' );
define( 'JB_HEALTH_VERSION', '1.3.0' );
define( 'JB_HEALTH_SCHEMA', 1 );

/**
 * Read-only site-health reporter.
 */
final class JB_Site_Health {

	/** Wire up the REST route. */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
	}

	/** Register GET /wp-json/jb-health/v1/report. */
	public static function register_routes() {
		register_rest_route(
			'jb-health/v1',
			'/report',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'handle_report' ),
				'permission_callback' => array( __CLASS__, 'authorise' ),
				'args'                => array(
					// Update transients can be stale. Opt in to a live refresh when the
					// caller would rather pay the latency than read a stale figure.
					'refresh' => array(
						'default'           => false,
						'sanitize_callback' => 'rest_sanitize_boolean',
					),
				),
			)
		);
	}

	// ----------------------------------------------------------------- //
	// Authentication
	// ----------------------------------------------------------------- //

	/**
	 * Accept only a valid fleet-signed token.
	 *
	 * Read the token from Authorization: Bearer, falling back to X-JB-Health-Token
	 * because some hosts (LiteSpeed/cPanel in particular) strip Authorization
	 * before it reaches PHP.
	 *
	 * @return true|WP_Error
	 */
	public static function authorise( $request ) {
		$token = '';

		$auth = $request->get_header( 'authorization' );
		if ( is_string( $auth ) && preg_match( '/^Bearer\s+(.+)$/i', trim( $auth ), $m ) ) {
			$token = $m[1];
		}
		if ( '' === $token ) {
			$alt = $request->get_header( 'x_jb_health_token' );
			if ( is_string( $alt ) ) {
				$token = trim( $alt );
			}
		}

		if ( '' !== $token && self::verify_signed_token( $token ) ) {
			return true;
		}

		// Same generic message either way — never reveal whether the token was
		// malformed, expired, or simply wrong.
		return new WP_Error( 'jb_health_unauthorised', 'Unauthorised.', array( 'status' => 401 ) );
	}

	/**
	 * Verify a fleet-signed token: jb1.<UTCdate:Ymd>.<base64url Ed25519 signature>.
	 *
	 * The signature must cover JB_HEALTH_SIGN_CONTEXT.<date> under ANY of the
	 * embedded public keys, and the date must sit within +/-1 day of the server's
	 * UTC date (grace for clock skew). Daily rotation falls out of that window: a
	 * captured token stops verifying on its own after roughly a day.
	 *
	 * Returns false rather than throwing, so anything malformed just 401s.
	 *
	 * @param string $token Candidate token.
	 * @return bool
	 */
	private static function verify_signed_token( $token ) {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return false;
		}
		if ( ! preg_match( '/^jb1\.([0-9]{8})\.([A-Za-z0-9_-]+)$/', (string) $token, $m ) ) {
			return false;
		}

		$date = $m[1];
		$sig  = self::b64url_decode( $m[2] );

		if ( false === $sig || SODIUM_CRYPTO_SIGN_BYTES !== strlen( $sig ) ) {
			return false;
		}

		// Check the cheap, key-independent condition before touching any crypto.
		$allowed = array(
			gmdate( 'Ymd', time() - DAY_IN_SECONDS ),
			gmdate( 'Ymd' ),
			gmdate( 'Ymd', time() + DAY_IN_SECONDS ),
		);
		if ( ! in_array( $date, $allowed, true ) ) {
			return false;
		}

		$message = JB_HEALTH_SIGN_CONTEXT . $date;

		// Accept a signature from any key currently in the list — that overlap is
		// what lets a rotation roll across the fleet gradually instead of all at
		// once. Deliberately no early return on a bad key: one malformed entry
		// must not shadow a good one further down.
		foreach ( self::signing_pubkeys() as $pub_b64 ) {
			$pk = base64_decode( (string) $pub_b64, true );
			if ( false === $pk || SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES !== strlen( $pk ) ) {
				continue;
			}
			if ( sodium_crypto_sign_verify_detached( $sig, $message, $pk ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * The accepted fleet public keys, as a list of base64 strings.
	 *
	 * Tolerates a bare string so a site still carrying the pre-1.1 constant — or
	 * a wp-config.php override written against it — keeps working rather than
	 * silently 401ing every request.
	 *
	 * @return string[]
	 */
	private static function signing_pubkeys() {
		$keys = array();

		if ( defined( 'JB_HEALTH_SIGNING_PUBKEYS' ) ) {
			$keys = (array) JB_HEALTH_SIGNING_PUBKEYS;
		} elseif ( defined( 'JB_HEALTH_SIGNING_PUBKEY' ) ) {
			$keys = array( JB_HEALTH_SIGNING_PUBKEY );
		}

		return array_filter( array_map( 'strval', $keys ) );
	}

	/** URL-safe base64 decode (accepts -_ and missing padding). False on garbage. */
	private static function b64url_decode( $s ) {
		$s   = strtr( (string) $s, '-_', '+/' );
		$pad = strlen( $s ) % 4;
		if ( $pad ) {
			$s .= str_repeat( '=', 4 - $pad );
		}
		return base64_decode( $s, true );
	}

	// ----------------------------------------------------------------- //
	// Report
	// ----------------------------------------------------------------- //

	/**
	 * Build the full payload.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public static function handle_report( $request ) {
		$refresh = (bool) $request->get_param( 'refresh' );

		$payload = array(
			'ok'             => true,
			'schema_version' => JB_HEALTH_SCHEMA,
			'plugin_version' => JB_HEALTH_VERSION,
			'generated_at'   => gmdate( 'c' ),
			'site'           => self::site_info(),
			'wordpress'      => self::wordpress_info( $refresh ),
			'php'            => self::php_info(),
			'plugins'        => self::plugin_info( $refresh ),
			'themes'         => self::theme_info( $refresh ),
			'hardening'      => self::hardening_info(),
			'brute_force'    => self::brute_force_info(),
		);

		$response = new WP_REST_Response( $payload, 200 );
		// This is per-site operational data — never let a proxy or CDN hold it.
		$response->header( 'Cache-Control', 'no-store, private' );
		return $response;
	}

	/**
	 * Identity of the site answering. The caller compares `home` against the
	 * domain it asked about, so a staging box can't silently answer for prod.
	 */
	private static function site_info() {
		return array(
			'siteurl'         => get_site_url(),
			'home'            => get_home_url(),
			'is_multisite'    => is_multisite(),
			'server_software' => isset( $_SERVER['SERVER_SOFTWARE'] )
				? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) )
				: null,
		);
	}

	/** WordPress version + whether core has an update waiting. */
	private static function wordpress_info( $refresh ) {
		global $wp_version;

		$out = array(
			'version'          => $wp_version,
			'latest'           => null,
			'update_available' => null,
			'checked_at'       => null,
			'reason'           => null,
		);

		if ( ! function_exists( 'get_core_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( $refresh && function_exists( 'wp_version_check' ) ) {
			wp_version_check( array(), true );
		}

		$transient = get_site_transient( 'update_core' );
		if ( ! $transient || empty( $transient->updates ) ) {
			$out['reason'] = 'core update transient not populated; WordPress has not run its update check yet';
			return $out;
		}

		$out['checked_at'] = isset( $transient->last_checked ) ? (int) $transient->last_checked : null;

		foreach ( $transient->updates as $update ) {
			// 'latest' means this install is current; 'upgrade' means one is offered.
			if ( isset( $update->response ) && 'upgrade' === $update->response && ! empty( $update->current ) ) {
				$out['latest']           = $update->current;
				$out['update_available'] = true;
				return $out;
			}
		}

		$out['latest']           = $wp_version;
		$out['update_available'] = false;
		return $out;
	}

	/**
	 * PHP version as the SITE actually runs it.
	 *
	 * This is the value WP-CLI over SSH gets wrong: on cPanel MultiPHP the shell
	 * default is frequently a different build from the one serving the domain
	 * (e.g. ea-php82 for web against a newer CLI). Running inside WordPress means
	 * phpversion() is the web runtime by definition.
	 */
	private static function php_info() {
		return array(
			'version'     => phpversion(),
			'major_minor' => implode( '.', array_slice( explode( '.', phpversion() ), 0, 2 ) ),
			'sapi'        => PHP_SAPI,
		);
	}

	/**
	 * Active plugin count plus everything with an update waiting, each classified
	 * by WHO OWNS THE ACTION.
	 *
	 * A bare "17 plugins behind" reads as neglect, when in reality the list mixes
	 * four very different situations. Classifying them is not softening the
	 * finding — it is the accurate version of it:
	 *
	 *   ready    free, and the new version is inside the composer constraint.
	 *            Ours to action.
	 *   held     composer deliberately pins it below the new version (e.g.
	 *            wp-mail-smtp ^3.6 against a 4.x release). A recorded decision,
	 *            not a lapse.
	 *   licence  premium/third-party. Usually blocked on a licence renewal, which
	 *            is the client's call — and worth surfacing loudly, because a
	 *            lapsed licence means no more security updates.
	 *   unpinned free, but composer records no constraint, so nobody has decided.
	 *
	 * Custom plugins never appear here at all: with no update channel, WordPress
	 * has nothing to compare against.
	 *
	 * Nothing is omitted from `updates` — the classification only adds context.
	 */
	private static function plugin_info( $refresh ) {
		$out = array(
			'active_count' => null,
			'update_count' => null,
			'updates'      => array(),
			'groups'       => array( 'ready' => 0, 'held' => 0, 'licence' => 0, 'unpinned' => 0 ),
			'composer'     => null,
			'checked_at'   => null,
			'reason'       => null,
		);

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		if ( ! function_exists( 'get_plugin_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( $refresh && function_exists( 'wp_update_plugins' ) ) {
			wp_update_plugins();
		}

		$active             = (array) get_option( 'active_plugins', array() );
		$out['active_count'] = count( $active );

		$transient = get_site_transient( 'update_plugins' );
		if ( ! $transient ) {
			$out['reason'] = 'plugin update transient not populated; WordPress has not run its update check yet';
			return $out;
		}
		$out['checked_at'] = isset( $transient->last_checked ) ? (int) $transient->last_checked : null;

		$updates = get_plugin_updates();
		if ( ! is_array( $updates ) ) {
			$out['reason'] = 'get_plugin_updates() returned no data';
			return $out;
		}

		$composer         = self::composer_requires();
		$out['composer']  = $composer['path'];

		foreach ( $updates as $file => $data ) {
			$slug    = dirname( $file );
			$new     = isset( $data->update->new_version ) ? $data->update->new_version : null;
			$source  = self::plugin_source( isset( $data->update ) ? $data->update : null );
			$rawcon  = isset( $composer['require'][ $slug ] ) ? $composer['require'][ $slug ] : null;
			$class   = self::classify_update( $source, $rawcon, $new );

			$out['updates'][] = array(
				'name'       => isset( $data->Name ) ? $data->Name : $file, // phpcs:ignore WordPress.NamingConventions.ValidVariableName
				'slug'       => $slug,
				'current'    => isset( $data->Version ) ? $data->Version : null, // phpcs:ignore WordPress.NamingConventions.ValidVariableName
				'new'        => $new,
				'source'     => $source,       // wporg | premium
				'constraint' => $rawcon,       // composer constraint, or null
				'class'      => $class,        // ready | held | licence | unpinned
			);
			if ( isset( $out['groups'][ $class ] ) ) {
				++$out['groups'][ $class ];
			}
		}
		$out['update_count'] = count( $out['updates'] );

		return $out;
	}

	/**
	 * Free wp.org plugin, or premium/third-party?
	 *
	 * wp.org updates carry an `id` of "w.org/plugins/<slug>" and ship from
	 * downloads.wordpress.org. Premium plugins self-host (Freemius, vendor
	 * domains) and usually carry no `id` at all. Either signal alone is enough.
	 */
	private static function plugin_source( $update ) {
		if ( ! $update ) {
			return 'premium';
		}
		$id = isset( $update->id ) ? (string) $update->id : '';
		if ( 0 === strpos( $id, 'w.org/plugins/' ) ) {
			return 'wporg';
		}
		$package = isset( $update->package ) ? (string) $update->package : '';
		$host    = $package ? wp_parse_url( $package, PHP_URL_HOST ) : '';
		if ( $host && false !== stripos( $host, 'wordpress.org' ) ) {
			return 'wporg';
		}
		return 'premium';
	}

	/** Decide who owns the action for one outdated plugin. */
	private static function classify_update( $source, $constraint, $new ) {
		if ( 'premium' === $source ) {
			return 'licence';
		}
		// No constraint, a wildcard, or a branch alias — nobody has recorded a
		// decision, so this is simply unmanaged drift.
		if ( ! $constraint || '*' === $constraint || 0 === strpos( $constraint, 'dev-' ) ) {
			return 'unpinned';
		}
		$allowed = self::constraint_allows( $constraint, $new );
		if ( null === $allowed ) {
			// Constraint form we do not parse. Say "unpinned" rather than invent a
			// verdict — a wrong "held" would excuse a genuinely stale plugin.
			return 'unpinned';
		}
		return $allowed ? 'ready' : 'held';
	}

	/**
	 * Does $version satisfy $constraint?
	 *
	 * Deliberately handles only caret and tilde ranges — the two forms Juicebox
	 * repos actually use — and returns null for anything else so the caller can
	 * degrade honestly instead of guessing. Reimplementing Composer's full
	 * resolver inside a reporting plugin would be far more risk than value.
	 *
	 * @return bool|null
	 */
	private static function constraint_allows( $constraint, $version ) {
		if ( ! $version || ! preg_match( '/^([\^~])\s*([0-9]+)(?:\.([0-9]+))?/', trim( $constraint ), $m ) ) {
			return null;
		}
		if ( ! preg_match( '/^([0-9]+)(?:\.([0-9]+))?/', (string) $version, $v ) ) {
			return null;
		}
		$op       = $m[1];
		$cmaj     = (int) $m[2];
		$cmin     = isset( $m[3] ) ? (int) $m[3] : 0;
		$vmaj     = (int) $v[1];
		$vmin     = isset( $v[2] ) ? (int) $v[2] : 0;

		// Below the floor is never allowed, whichever operator.
		if ( $vmaj < $cmaj || ( $vmaj === $cmaj && $vmin < $cmin ) ) {
			return false;
		}
		if ( '^' === $op ) {
			return $vmaj === $cmaj;              // ^3.6 -> >=3.6 <4.0
		}
		return $vmaj === $cmaj && $vmin === $cmin; // ~3.6 -> >=3.6 <3.7
	}

	/**
	 * Locate and parse the site's composer.json.
	 *
	 * Walks up from ABSPATH because Bedrock keeps the manifest above the
	 * webroot (www/wp/ -> composer.json two levels up). Returns the require map
	 * keyed by bare plugin slug, so "wpackagist-plugin/relevanssi" matches the
	 * "relevanssi" plugin directory.
	 *
	 * @return array{path:?string, require:array<string,string>}
	 */
	private static function composer_requires() {
		$dir = defined( 'ABSPATH' ) ? rtrim( ABSPATH, '/\\' ) : '';
		for ( $i = 0; $i < 5 && $dir; $i++ ) {
			$candidate = $dir . '/composer.json';
			if ( is_readable( $candidate ) ) {
				$json = json_decode( (string) file_get_contents( $candidate ), true ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				if ( is_array( $json ) && isset( $json['require'] ) && is_array( $json['require'] ) ) {
					$map = array();
					foreach ( $json['require'] as $pkg => $constraint ) {
						$slug = substr( strrchr( '/' . $pkg, '/' ), 1 );
						if ( '' !== $slug ) {
							$map[ $slug ] = trim( (string) $constraint );
						}
					}
					return array( 'path' => $candidate, 'require' => $map );
				}
			}
			$parent = dirname( $dir );
			if ( $parent === $dir ) {
				break;
			}
			$dir = $parent;
		}
		return array( 'path' => null, 'require' => array() );
	}

	/** Themes with an update waiting — same idea, lower stakes. */
	private static function theme_info( $refresh ) {
		$out = array(
			'update_count' => null,
			'updates'      => array(),
			'reason'       => null,
		);

		if ( ! function_exists( 'get_theme_updates' ) ) {
			require_once ABSPATH . 'wp-admin/includes/update.php';
		}
		if ( $refresh && function_exists( 'wp_update_themes' ) ) {
			wp_update_themes();
		}

		$updates = get_theme_updates();
		if ( ! is_array( $updates ) ) {
			$out['reason'] = 'get_theme_updates() returned no data';
			return $out;
		}

		foreach ( $updates as $stylesheet => $theme ) {
			$out['updates'][] = array(
				'name'    => $theme->get( 'Name' ),
				'slug'    => $stylesheet,
				'current' => $theme->get( 'Version' ),
				'new'     => isset( $theme->update['new_version'] ) ? $theme->update['new_version'] : null,
			);
		}
		$out['update_count'] = count( $out['updates'] );

		return $out;
	}

	/** The hardening flags the report asks about. */
	private static function hardening_info() {
		return array(
			'disallow_file_edit'    => array(
				'defined' => defined( 'DISALLOW_FILE_EDIT' ),
				// Undefined is meaningful, not unknown: WordPress defaults to
				// allowing the built-in file editors.
				'value'   => defined( 'DISALLOW_FILE_EDIT' ) ? (bool) DISALLOW_FILE_EDIT : false,
			),
			'disallow_file_mods'    => array(
				'defined' => defined( 'DISALLOW_FILE_MODS' ),
				'value'   => defined( 'DISALLOW_FILE_MODS' ) ? (bool) DISALLOW_FILE_MODS : false,
			),
			'uploads_php_execution' => self::uploads_php_execution(),
			'blog_public'           => (bool) get_option( 'blog_public' ),
			'debug_display'         => defined( 'WP_DEBUG_DISPLAY' ) ? (bool) WP_DEBUG_DISPLAY : null,
		);
	}

	/**
	 * Is PHP execution blocked inside the uploads directory?
	 *
	 * This answers `true` or `null` — never `false`. Reading files can PROVE a
	 * rule exists; it can never prove one does not, because the rule may equally
	 * live in an Apache/LiteSpeed vhost block, an nginx server block, a WAF, or
	 * a php-fpm pool config — none of which PHP can read. The previous version
	 * returned `false` whenever it found no file rule on a non-nginx server,
	 * which reported sites hardened at the document root (a very common shape)
	 * as "Not blocked" in a client-facing report.
	 *
	 * Two places are inspected, both of which PHP genuinely can read:
	 *
	 *   1. uploads/.htaccess and uploads/.user.ini — a rule scoped to this
	 *      directory, so any deny-ish directive counts.
	 *   2. every .htaccess from the uploads directory up to the document root —
	 *      here a rule must name BOTH the uploads path and a PHP-ish extension
	 *      before it counts, so an unrelated deny elsewhere in the file cannot
	 *      be mistaken for uploads hardening.
	 *
	 * When neither finds anything the answer is `null` with a reason naming what
	 * was inspected. The authoritative negative is an HTTP request for a .php
	 * under uploads, which the report's caller performs — it tests behaviour
	 * rather than inferring it, and it works on sites without this plugin.
	 *
	 * Paths in the output are relative to the document root, never absolute:
	 * they reach a client-facing report, and absolute server paths are exactly
	 * what the report pipeline strips as connector infrastructure.
	 */
	private static function uploads_php_execution() {
		$out = array(
			'blocked'   => null,
			'evidence'  => null,
			'reason'    => null,
			'inspected' => array(),
		);

		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['error'] ) || empty( $uploads['basedir'] ) ) {
			$out['reason'] = 'uploads directory not resolvable';
			return $out;
		}

		$base = self::real_dir( $uploads['basedir'] );
		if ( ! $base ) {
			$out['reason'] = 'uploads directory not resolvable on disk';
			return $out;
		}

		$root = self::document_root();

		// 1. Rules scoped to the uploads directory itself.
		$htaccess = $base . '/.htaccess';
		$userini  = $base . '/.user.ini';

		if ( is_readable( $htaccess ) ) {
			$out['inspected'][] = self::relative_to( $htaccess, $root );
			$contents           = (string) file_get_contents( $htaccess ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( preg_match( '/(deny|forbidden|SetHandler|php_flag|RemoveHandler|<Files)/i', $contents ) ) {
				$out['blocked']  = true;
				$out['evidence'] = self::relative_to( $htaccess, $root ) . ' contains a PHP-deny rule';
				return $out;
			}
		}
		if ( file_exists( $userini ) ) {
			$out['inspected'][] = self::relative_to( $userini, $root );
			$out['blocked']     = true;
			$out['evidence']    = self::relative_to( $userini, $root ) . ' present';
			return $out;
		}

		// 2. Ancestor .htaccess files, up to and including the document root.
		//    A rule only counts here if it names the uploads path AND a
		//    server-side script extension — anything looser would read an
		//    unrelated deny block as uploads hardening.
		$rel = trim( self::relative_to( $base, $root ), '/' );
		if ( '' !== $rel ) {
			foreach ( self::ancestor_htaccess( $base, $root ) as $file ) {
				$out['inspected'][] = self::relative_to( $file, $root );
				$contents           = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				if ( self::denies_php_under( $contents, $rel ) ) {
					$out['blocked']  = true;
					$out['evidence'] = self::relative_to( $file, $root )
						. ' denies PHP under ' . $rel;
					return $out;
				}
			}
		}

		$server = isset( $_SERVER['SERVER_SOFTWARE'] )
			? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) )
			: '';

		$out['reason'] = 'no rule found in '
			. ( $out['inspected'] ? implode( ', ', $out['inspected'] ) : 'any readable .htaccess/.user.ini' )
			. ( $server ? ' (server: ' . $server . ')' : '' )
			. ' — a rule in a vhost, nginx server block or WAF is not readable from PHP,'
			. ' so absence of a file rule does not mean execution is allowed';
		return $out;
	}

	/**
	 * Does this .htaccess deny PHP under the given uploads-relative path?
	 *
	 * Line-oriented on purpose, and all three conditions must hold on the SAME
	 * line, because an .htaccess is a pile of unrelated directives and matching
	 * across them invents rules nobody wrote:
	 *
	 *   - it names the uploads path, so a deny aimed at wp-config.php or at
	 *     another directory is not read as uploads hardening;
	 *   - it names a server-side script extension;
	 *   - it actually denies — [F], Require ... denied, SetHandler, php_flag,
	 *     RemoveHandler, 403. A RewriteRule that merely rewrites is not a block.
	 *
	 * Comments are skipped: a line describing the intent is not the rule. The
	 * extension test deliberately does not require the dot to sit next to the
	 * extension — the real-world form is
	 * `RewriteRule ^app/uploads/.*\.(?:php|phtml|…)$ - [F,L,NC]`, where what
	 * follows the dot is `(?:`, not `php`.
	 *
	 * @param string $contents Raw .htaccess text.
	 * @param string $rel      Uploads dir relative to the document root, e.g. "app/uploads".
	 * @return bool
	 */
	private static function denies_php_under( $contents, $rel ) {
		$path_re = '/' . preg_quote( $rel, '/' ) . '/i';
		$ext_re  = '/(?:^|[^a-z0-9])(?:php[0-9]?|phtml|pht|phps|phar)(?:$|[^a-z0-9])/i';
		$deny_re = '/(?:\[[^\]]*\bF\b[^\]]*\]|deny|denied|forbidden|SetHandler|RemoveHandler|php_flag|\b403\b)/i';

		foreach ( preg_split( '/\r\n|\r|\n/', (string) $contents ) as $line ) {
			$trimmed = ltrim( $line );
			if ( '' === $trimmed || '#' === $trimmed[0] ) {
				continue;
			}
			if ( preg_match( $path_re, $line )
				&& preg_match( $ext_re, $line )
				&& preg_match( $deny_re, $line ) ) {
				return true;
			}
		}
		return false;
	}

	/** realpath() for a directory, or '' when it does not resolve. */
	private static function real_dir( $path ) {
		$real = realpath( (string) $path );
		return ( $real && is_dir( $real ) ) ? rtrim( $real, '/' ) : '';
	}

	/**
	 * The document root, resolved.
	 *
	 * DOCUMENT_ROOT is the honest answer when the SAPI supplies one. Falling
	 * back to ABSPATH's parent covers Bedrock, where WordPress lives one level
	 * below the web root in www/wp.
	 */
	private static function document_root() {
		$root = isset( $_SERVER['DOCUMENT_ROOT'] )
			? self::real_dir( sanitize_text_field( wp_unslash( $_SERVER['DOCUMENT_ROOT'] ) ) )
			: '';
		if ( $root ) {
			return $root;
		}
		return self::real_dir( dirname( rtrim( ABSPATH, '/' ) ) );
	}

	/**
	 * Readable .htaccess files between $from (exclusive) and $root (inclusive).
	 *
	 * Walks upward, nearest first, so the most specific rule wins. Bounded at
	 * eight levels and stopped at the document root so a misconfigured root can
	 * never send this climbing to /.
	 *
	 * @return string[]
	 */
	private static function ancestor_htaccess( $from, $root ) {
		$found = array();
		$dir   = $from;
		for ( $i = 0; $i < 8; $i++ ) {
			$parent = dirname( $dir );
			if ( $parent === $dir || '' === $parent || '/' === $parent ) {
				break;
			}
			$file = $parent . '/.htaccess';
			if ( is_readable( $file ) ) {
				$found[] = $file;
			}
			if ( $root && $parent === $root ) {
				break;
			}
			$dir = $parent;
		}
		return $found;
	}

	/**
	 * A path expressed relative to the document root.
	 *
	 * Absolute server paths are connector infrastructure — the report pipeline
	 * strips them, and they mean nothing to a client. When the path is not under
	 * the root, only the basename survives.
	 */
	private static function relative_to( $path, $root ) {
		$path = (string) $path;
		if ( $root && 0 === strpos( $path, $root . '/' ) ) {
			return substr( $path, strlen( $root ) + 1 );
		}
		return basename( $path );
	}

	/**
	 * Brute-force activity over the last 30 days.
	 *
	 * Detects the security plugin in play and reads its own log tables. Where no
	 * supported plugin is present the answer is an honest null naming what it
	 * would need — never a zero, which would read as "no attacks" rather than
	 * "not measured".
	 */
	private static function brute_force_info() {
		global $wpdb;

		$out = array(
			'source'        => null,
			'window_days'   => 30,
			'lockouts'      => null,
			'failed_logins' => null,
			'reason'        => null,
		);

		$since     = gmdate( 'Y-m-d H:i:s', time() - ( 30 * DAY_IN_SECONDS ) );
		$lockouts  = $wpdb->prefix . 'itsec_lockouts';
		$itsec_log = $wpdb->prefix . 'itsec_logs';

		// Solid Security / iThemes Security (Pro).
		if ( self::table_exists( $lockouts ) ) {
			$out['source'] = 'solid-security';

			// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name cannot be bound.
			$out['lockouts'] = (int) $wpdb->get_var(
				$wpdb->prepare( "SELECT COUNT(*) FROM `{$lockouts}` WHERE lockout_start_gmt >= %s", $since )
			);

			if ( self::table_exists( $itsec_log ) ) {
				$out['failed_logins'] = (int) $wpdb->get_var(
					$wpdb->prepare(
						"SELECT COUNT(*) FROM `{$itsec_log}` WHERE module = %s AND timestamp >= %s",
						'brute_force',
						$since
					)
				);
			}
			// phpcs:enable
			return $out;
		}

		// Wordfence.
		$wf_blocks = $wpdb->base_prefix . 'wfBlocks7';
		if ( self::table_exists( $wf_blocks ) ) {
			$out['source'] = 'wordfence';
			// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$out['lockouts'] = (int) $wpdb->get_var(
				$wpdb->prepare( "SELECT COUNT(*) FROM `{$wf_blocks}` WHERE ctime >= %d", time() - ( 30 * DAY_IN_SECONDS ) )
			);
			// phpcs:enable
			return $out;
		}

		$out['reason'] = 'no supported security plugin detected (Solid Security or Wordfence required)';
		return $out;
	}

	/** Does a table exist? Guards every raw-table read above. */
	private static function table_exists( $table ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		return (bool) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
	}
}

JB_Site_Health::init();
