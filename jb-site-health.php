<?php
/**
 * Plugin Name: JB Site Health
 * Description: Read-only site-health endpoint for the Juicebox Digital Support Plan report. Returns the data points that cannot be observed from outside the site — WordPress/PHP version, plugin update status, hardening flags, and brute-force counts.
 * Version:     1.7.0
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
define( 'JB_HEALTH_VERSION', '1.7.0' );
define( 'JB_HEALTH_SCHEMA', 1 );

/**
 * Read-only site-health reporter.
 */
final class JB_Site_Health {

	/** Wire up the REST routes, and the 401-before-400 guard they depend on. */
	public static function init() {
		add_action( 'rest_api_init', array( __CLASS__, 'register_routes' ) );
		add_filter( 'rest_request_before_callbacks', array( __CLASS__, 'shield_unauthorised' ), 10, 3 );
	}

	/** Register GET /wp-json/jb-health/v1/report and /wp-json/jb-health/v1/forms/entry. */
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

		/**
		 * Entry lookup — did ONE known submission land, and what did Gravity
		 * Forms record about its notifications?
		 *
		 * Same permission callback as /report. Arguments are declared here
		 * rather than checked in the callback so WordPress rejects a malformed
		 * request before any of our code runs: a bad arg comes back as its own
		 * `rest_invalid_param` (400) carrying our code and message in
		 * `data.details`. See shield_unauthorised() for why an unauthenticated
		 * caller still gets a 401 out of that path.
		 */
		register_rest_route(
			'jb-health/v1',
			'/forms/entry',
			array(
				'methods'             => 'GET',
				'callback'            => array( __CLASS__, 'handle_entry_lookup' ),
				'permission_callback' => array( __CLASS__, 'authorise' ),
				'args'                => array(
					'form'  => array(
						'required'          => true,
						'validate_callback' => array( __CLASS__, 'validate_form_id' ),
						'sanitize_callback' => 'absint',
					),
					'stamp' => array(
						'required'          => true,
						'validate_callback' => array( __CLASS__, 'validate_stamp' ),
						'sanitize_callback' => 'sanitize_text_field',
					),
					// A week is already generous for "did the submission I just
					// made land"; the window is what bounds the LIKE scan.
					'hours' => array(
						'default'           => 24,
						'validate_callback' => array( __CLASS__, 'validate_hours' ),
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		/**
		 * Delivery events — SendGrid's Event Webhook posts here (added 1.7.0).
		 *
		 * Authenticated by SendGrid's own signature over the body, NOT by the
		 * fleet token: the caller is SendGrid, and the fleet key must stay a
		 * read-only credential. No `args` on purpose — the body is a raw JSON
		 * array that is verified before it is parsed (see handle_mail_events).
		 */
		register_rest_route(
			'jb-health/v1',
			'/mail-events',
			array(
				'methods'             => 'POST',
				'callback'            => array( __CLASS__, 'handle_mail_events' ),
				'permission_callback' => '__return_true',
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
	 * Put 401 back in front of 400.
	 *
	 * WordPress does NOT check permission first. WP_REST_Server::dispatch()
	 * runs has_valid_params() and sanitize_params() itself and hands the
	 * resulting WP_Error to respond_to_request(), which then skips the
	 * permission_callback entirely because a response already exists. The
	 * observable effect on an authenticated route is that a stranger sending a
	 * malformed argument gets a descriptive 400 while the same stranger sending
	 * a well-formed one gets 401 — and the difference between those two answers
	 * is a free oracle for the argument format, handed out before any
	 * credential is ever examined.
	 *
	 * On /report that never mattered: its only argument cannot fail. The entry
	 * lookup takes a stamp whose format is the thing protecting it, so the
	 * oracle is worth closing.
	 *
	 * This runs on every REST request on the site, so it returns on the first
	 * line for the normal case (no error yet) and only acts on handlers whose
	 * permission callback is ours — it never touches another plugin's route,
	 * and an authorised caller still gets the descriptive 400 it needs.
	 *
	 * @param mixed           $response Response or error so far — null when nothing has failed.
	 * @param array           $handler  Route handler matched for the request.
	 * @param WP_REST_Request $request  The request.
	 * @return mixed
	 */
	public static function shield_unauthorised( $response, $handler, $request ) {
		if ( ! is_wp_error( $response ) ) {
			return $response;
		}
		if ( empty( $handler['permission_callback'] ) || array( __CLASS__, 'authorise' ) !== $handler['permission_callback'] ) {
			return $response;
		}

		$permission = self::authorise( $request );

		return is_wp_error( $permission ) ? $permission : $response;
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
			'forms'          => self::forms_info(),
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

	// ----------------------------------------------------------------- //
	// Forms
	// ----------------------------------------------------------------- //

	/**
	 * Form health, read-only.
	 *
	 * Forms are the thing that breaks quietly after a WordPress, PHP or plugin
	 * update: the page still renders, the visitor still sees "thanks", and the
	 * first we hear of it is a client asking why nobody called them back. None
	 * of that is visible from outside the site.
	 *
	 * Everything here is observation, never a verdict. This function does not
	 * submit anything, does not send mail, and does not decide whether a form is
	 * "broken" — it reports the configuration and the entry volume, and lets the
	 * caller compare across months. Two signals do most of the work:
	 *
	 *   - `notifications[].active` false, or a `to` pointing somewhere stale,
	 *     is a delivery failure that has already happened.
	 *   - `entries_30d` collapsing against `entries_prev_30d` on a form that
	 *     used to receive steady traffic is the fingerprint of a form that
	 *     started failing silently.
	 *
	 * Gravity Forms only for now — it is what the fleet runs. Any other form
	 * plugin returns a reason rather than a misleading empty list.
	 *
	 * @return array
	 */
	private static function forms_info() {
		$out = array(
			'engine'                => null,
			'engine_version'        => null,
			'recaptcha_v3_sitewide' => null,
			'mailer'                => self::mailer_info(),
			'count'                 => null,
			'items'                 => null,
			'reason'                => null,
		);

		// What the sending provider said about the last 30 days of mail (1.7.0):
		// delivered / bounced / dropped counts from SendGrid's Event Webhook.
		// Site-wide, not per form — events carry the recipient, not the form.
		$out['mailer']['delivery_30d'] = self::mail_delivery_30d();

		if ( ! class_exists( 'GFAPI' ) || ! class_exists( 'GFCommon' ) ) {
			$out['reason'] = 'Gravity Forms is not active on this site; no other form plugin is supported yet';
			return $out;
		}

		$out['engine']         = 'gravityforms';
		$out['engine_version'] = property_exists( 'GFCommon', 'version' ) ? GFCommon::$version : null;

		// The reCAPTCHA add-on can enable v3 site-wide. That loads the script on
		// every page but only gates forms that carry a captcha field, so the two
		// facts are reported separately rather than conflated.
		$recaptcha = get_option( 'gravityformsaddon_gravityformsrecaptcha_settings' );
		if ( is_array( $recaptcha ) ) {
			$out['recaptcha_v3_sitewide'] = ! empty( $recaptcha['recaptcha_keys_status_v3'] );
		}

		$forms = GFAPI::get_forms( null, false );
		if ( ! is_array( $forms ) ) {
			$out['reason'] = 'Gravity Forms returned no form list';
			return $out;
		}

		$stats = self::entry_stats();
		$notes = self::notification_stats();
		$items = array();

		foreach ( $forms as $form ) {
			$id = isset( $form['id'] ) ? (int) $form['id'] : 0;
			$s  = isset( $stats[ $id ] ) ? $stats[ $id ] : null;

			$items[] = array(
				'id'                => $id,
				'title'             => isset( $form['title'] ) ? $form['title'] : null,
				'active'            => isset( $form['is_active'] ) ? (bool) $form['is_active'] : null,
				'captcha'           => self::form_captcha( $form, $out['recaptcha_v3_sitewide'] ),
				'notifications'     => self::form_notifications( $form ),
				'entries_total'     => $s ? (int) $s['total'] : 0,
				'entries_30d'       => $s ? (int) $s['last30'] : 0,
				'entries_prev_30d'  => $s ? (int) $s['prev30'] : 0,
				'last_entry'        => $s && $s['last_entry'] ? gmdate( 'c', strtotime( $s['last_entry'] . ' UTC' ) ) : null,
				// The site's own email log for this form: what Gravity Forms
				// recorded about every notification it tried to send in the last
				// 30 days. Added 1.6.0; purely additive, schema unchanged.
				'notifications_30d' => self::notification_window( $notes, $id ),
			);
		}

		$out['count'] = count( $items );
		$out['items'] = $items;

		if ( null === $stats ) {
			$out['reason'] = 'entry counts unavailable: the Gravity Forms entry table was not readable';
		}

		return $out;
	}

	/**
	 * What captcha protection applies to this form.
	 *
	 * There are two independent gates and they look nothing alike, so they are
	 * reported separately rather than collapsed into one boolean:
	 *
	 *   `field`        — a visible captcha FIELD placed on the form in the editor.
	 *   `recaptcha_v3` — the invisible reCAPTCHA v3 the add-on applies to every
	 *                    form once site keys are configured.
	 *
	 * The v3 setting is stored INVERTED, which is easy to get backwards: a form
	 * carries `gravityformsrecaptcha.disable-recaptchav3` only when someone has
	 * opted it OUT. No key means v3 is active. So v3 applies when site keys are
	 * configured AND the form has no opt-out — which is why an otherwise
	 * identical-looking form can be gated while its neighbour is not.
	 *
	 * Either gate makes the form impossible to exercise with an unattended
	 * submission, so the caller needs both to tell "tested and fine" apart from
	 * "never tested".
	 *
	 * @param array     $form      Gravity Forms form object.
	 * @param bool|null $v3_active Whether v3 site keys are configured at all.
	 * @return array
	 */
	private static function form_captcha( $form, $v3_active ) {
		$out = array(
			'field'        => false,
			'field_type'   => null,
			'recaptcha_v3' => null,
		);

		if ( null !== $v3_active ) {
			$opted_out = ! empty( $form['gravityformsrecaptcha']['disable-recaptchav3'] );
			$out['recaptcha_v3'] = $v3_active && ! $opted_out;
		}

		if ( empty( $form['fields'] ) || ! is_array( $form['fields'] ) ) {
			return $out;
		}
		foreach ( $form['fields'] as $field ) {
			$type = is_object( $field ) && isset( $field->type ) ? $field->type : null;
			if ( 'captcha' !== $type ) {
				continue;
			}
			$out['field'] = true;
			// captchaType: recaptcha / simple_captcha / math, absent means reCAPTCHA.
			$out['field_type'] = isset( $field->captchaType ) && $field->captchaType ? $field->captchaType : 'recaptcha';
			return $out;
		}
		return $out;
	}

	/**
	 * Where each notification is configured to go, and whether it is switched on.
	 *
	 * `to` is reported verbatim, merge tags and all ({admin_email}, or a field
	 * id when the form routes to an address the visitor typed). Resolving it
	 * would mean guessing, and a wrong address in a client-facing report is
	 * worse than an unresolved one.
	 *
	 * @param array $form Gravity Forms form object.
	 * @return array
	 */
	private static function form_notifications( $form ) {
		if ( empty( $form['notifications'] ) || ! is_array( $form['notifications'] ) ) {
			return array();
		}

		$out = array();
		foreach ( $form['notifications'] as $n ) {
			if ( ! is_array( $n ) ) {
				continue;
			}
			$out[] = array(
				'name'    => isset( $n['name'] ) ? $n['name'] : null,
				// GF omits isActive entirely on notifications that have never been
				// toggled, and those are active. Absent must not read as "off".
				'active'  => ! isset( $n['isActive'] ) || (bool) $n['isActive'],
				'event'   => isset( $n['event'] ) ? $n['event'] : null,
				'to_type' => isset( $n['toType'] ) ? $n['toType'] : null,
				'to'      => isset( $n['to'] ) ? $n['to'] : null,
			);
		}
		return $out;
	}

	/**
	 * Entry volume for every form, in one grouped query.
	 *
	 * Per-form queries would mean three round trips each, which on a site with
	 * forty forms turns a health check into a slow page. Trashed and spam rows
	 * are excluded so a spam wave cannot mask a form that stopped receiving
	 * genuine submissions.
	 *
	 * @return array|null Keyed by form id, or null if the table is unreadable.
	 */
	private static function entry_stats() {
		global $wpdb;

		$table = $wpdb->prefix . 'gf_entry';
		if ( ! self::table_exists( $table ) ) {
			return null;
		}

		$now    = time();
		$d30    = gmdate( 'Y-m-d H:i:s', $now - ( 30 * DAY_IN_SECONDS ) );
		$d60    = gmdate( 'Y-m-d H:i:s', $now - ( 60 * DAY_IN_SECONDS ) );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name cannot be bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT form_id,
				        COUNT(*) AS total,
				        SUM(date_created >= %s) AS last30,
				        SUM(date_created >= %s AND date_created < %s) AS prev30,
				        MAX(date_created) AS last_entry
				 FROM `{$table}`
				 WHERE status = 'active'
				 GROUP BY form_id",
				$d30,
				$d60,
				$d30
			),
			ARRAY_A
		);
		// phpcs:enable

		if ( ! is_array( $rows ) ) {
			return null;
		}

		$out = array();
		foreach ( $rows as $r ) {
			$out[ (int) $r['form_id'] ] = $r;
		}
		return $out;
	}

	/**
	 * Notification outcomes for every form over the last 60 days, in one query.
	 *
	 * This is the site's own email log. Gravity Forms writes one entry note per
	 * notification attempt (GFFormsModel::add_notification_note(), GF >= 2.4.14):
	 * sub_type 'success' when wp_mail() handed the message to the sending
	 * server, 'error' with the underlying reason when it did not. Counting those
	 * per form answers "are this form's real submissions being emailed?" without
	 * submitting anything — the only evidence available for a form an unattended
	 * check cannot exercise (a captcha gate, say), and the one that matters after
	 * an update: the form kept working for real people, or it did not.
	 *
	 * Accepted by the sending server is the honest ceiling: a bounce or a spam
	 * folder downstream is invisible here. The last error text is returned per
	 * form because it usually IS the diagnosis (an invalid TO address, an SMTP
	 * refusal). It is GF's own system message, never visitor input.
	 *
	 * Two windows, like entry_stats(): the current 30 days and the 30 before,
	 * so a caller can see a form's sends collapse rather than just read a zero.
	 *
	 * @return array {checked, reason, forms => [form_id => window]}
	 */
	private static function notification_stats() {
		global $wpdb;

		$out     = array(
			'checked' => false,
			'reason'  => null,
			'forms'   => array(),
		);
		$notes   = $wpdb->prefix . 'gf_entry_notes';
		$entries = $wpdb->prefix . 'gf_entry';

		if ( ! self::table_exists( $notes ) || ! self::table_exists( $entries ) ) {
			$out['reason'] = 'the Gravity Forms entry notes table is not present on this site';
			return $out;
		}
		if ( ! self::column_exists( $notes, 'sub_type' ) ) {
			$out['reason'] = 'the entry notes table has no sub_type column (Gravity Forms schema older than 2.3), so notification results cannot be classified';
			return $out;
		}

		$now = time();
		$d30 = gmdate( 'Y-m-d H:i:s', $now - ( 30 * DAY_IN_SECONDS ) );
		$d60 = gmdate( 'Y-m-d H:i:s', $now - ( 60 * DAY_IN_SECONDS ) );

		// The notes table carries no form id, so it is joined to the entry table
		// for it. Entry status is deliberately NOT filtered: a note exists only
		// because a send was attempted, and a later trash/spam flag on the entry
		// does not un-send the mail.
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table names cannot be bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT e.form_id, n.sub_type,
				        SUM(n.date_created >= %s) AS last30,
				        SUM(n.date_created < %s) AS prev30,
				        MAX(n.date_created) AS last_at
				 FROM `{$notes}` n
				 JOIN `{$entries}` e ON e.id = n.entry_id
				 WHERE n.note_type = 'notification' AND n.date_created >= %s
				 GROUP BY e.form_id, n.sub_type",
				$d30,
				$d30,
				$d60
			),
			ARRAY_A
		);
		// phpcs:enable

		if ( ! is_array( $rows ) ) {
			$out['reason'] = 'the Gravity Forms entry notes table was not readable';
			return $out;
		}

		foreach ( $rows as $r ) {
			$id  = (int) $r['form_id'];
			$sub = isset( $r['sub_type'] ) ? (string) $r['sub_type'] : '';
			if ( ! isset( $out['forms'][ $id ] ) ) {
				$out['forms'][ $id ] = self::empty_notification_window();
			}
			$last = empty( $r['last_at'] ) ? null : gmdate( 'c', strtotime( $r['last_at'] . ' UTC' ) );

			if ( 'success' === $sub ) {
				$out['forms'][ $id ]['sent']             = (int) $r['last30'];
				$out['forms'][ $id ]['prev_30d']['sent'] = (int) $r['prev30'];
				$out['forms'][ $id ]['last_sent_at']     = $last;
			} elseif ( 'error' === $sub ) {
				$out['forms'][ $id ]['failed']             = (int) $r['last30'];
				$out['forms'][ $id ]['prev_30d']['failed'] = (int) $r['prev30'];
				$out['forms'][ $id ]['last_failed_at']     = $last;
			}
			// An add-on can write a sub_type of its own; those are neither, and
			// are left out rather than guessed at.
		}

		// The most recent error text per form (30 days), because it usually names
		// the cause. Capped: an SMTP error can carry an entire server transcript.
		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table names cannot be bound.
		$errs = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT e.form_id, n.value
				 FROM `{$notes}` n
				 JOIN `{$entries}` e ON e.id = n.entry_id
				 WHERE n.note_type = 'notification' AND n.sub_type = 'error' AND n.date_created >= %s
				 ORDER BY n.id DESC
				 LIMIT 200",
				$d30
			),
			ARRAY_A
		);
		// phpcs:enable

		if ( is_array( $errs ) ) {
			foreach ( $errs as $r ) {
				$id = (int) $r['form_id'];
				if ( isset( $out['forms'][ $id ] ) && null === $out['forms'][ $id ]['last_error'] ) {
					$out['forms'][ $id ]['last_error'] = self::clip( isset( $r['value'] ) ? $r['value'] : '', 500 );
				}
			}
		}

		$out['checked'] = true;
		return $out;
	}

	/**
	 * The zero shape of a form's 30-day notification window. Every key present
	 * whether or not anything was sent, so a caller never tests for a missing
	 * counter; `checked` false plus a reason is how "not measured" is told apart
	 * from "nothing sent".
	 *
	 * @return array
	 */
	private static function empty_notification_window() {
		return array(
			'checked'        => true,
			'reason'         => null,
			'sent'           => 0,
			'failed'         => 0,
			'prev_30d'       => array(
				'sent'   => 0,
				'failed' => 0,
			),
			'last_sent_at'   => null,
			'last_failed_at' => null,
			'last_error'     => null,
		);
	}

	/**
	 * One form's view of notification_stats().
	 *
	 * @param array $stats   Result of notification_stats().
	 * @param int   $form_id Gravity Forms form id.
	 * @return array
	 */
	private static function notification_window( $stats, $form_id ) {
		if ( empty( $stats['checked'] ) ) {
			$w            = self::empty_notification_window();
			$w['checked'] = false;
			$w['reason']  = isset( $stats['reason'] ) ? $stats['reason'] : null;
			return $w;
		}
		return isset( $stats['forms'][ $form_id ] ) ? $stats['forms'][ $form_id ] : self::empty_notification_window();
	}

	/**
	 * How this site actually sends mail.
	 *
	 * A deactivated SMTP plugin is one of the quietest ways for every form on a
	 * site to stop delivering while still looking perfectly healthy, so the
	 * active flag matters more than the presence of the plugin.
	 *
	 * WP_ENV is reported alongside it because the Bedrock template ships a
	 * mu-plugin that deactivates SMTP plugins outside production by design —
	 * without that context, `active: false` on a staging box reads as a fault
	 * when it is the intended behaviour.
	 *
	 * @return array
	 */
	private static function mailer_info() {
		$out = array(
			'plugin' => null,
			'active' => null,
			'mailer' => null,
			'wp_env' => defined( 'WP_ENV' ) ? WP_ENV : null,
			'reason' => null,
		);

		// Slug => the plugin file WordPress knows it by.
		$known = array(
			'wp-mail-smtp'    => 'wp-mail-smtp/wp_mail_smtp.php',
			'post-smtp'       => 'post-smtp/postman-smtp.php',
			'easy-wp-smtp'    => 'easy-wp-smtp/easy-wp-smtp.php',
			'fluent-smtp'     => 'fluent-smtp/fluent-smtp.php',
			'wp-ses'          => 'wp-ses/wp-ses.php',
			'sendgrid'        => 'sendgrid-email-delivery-simplified/wpsendgrid.php',
		);

		if ( ! function_exists( 'is_plugin_active' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$installed = array_keys( get_plugins() );

		foreach ( $known as $slug => $file ) {
			if ( ! in_array( $file, $installed, true ) ) {
				continue;
			}
			$out['plugin'] = $slug;
			$out['active'] = is_plugin_active( $file );

			if ( 'wp-mail-smtp' === $slug ) {
				$settings = get_option( 'wp_mail_smtp' );
				if ( is_array( $settings ) && isset( $settings['mail']['mailer'] ) ) {
					$out['mailer'] = $settings['mail']['mailer'];
				}
			}

			if ( ! $out['active'] && $out['wp_env'] && 'production' !== $out['wp_env'] ) {
				$out['reason'] = 'installed but inactive; this site is not production, where the Bedrock template deactivates SMTP plugins by design';
			} elseif ( ! $out['active'] ) {
				$out['reason'] = 'installed but NOT active on a production site — mail is falling back to PHP mail()';
			}
			return $out;
		}

		$out['reason'] = 'no recognised SMTP plugin installed; mail goes through PHP mail() or a host-level relay';
		return $out;
	}

	// ----------------------------------------------------------------- //
	// Delivery events (SendGrid Event Webhook) — added 1.7.0
	// ----------------------------------------------------------------- //

	/**
	 * The subuser's Event Webhook verification key (base64 DER public key,
	 * copied from SendGrid → Settings → Mail Settings → Event Webhook).
	 *
	 * Constant, then environment, then option — so it can travel in the
	 * deployed .env like every other per-site secret, or be set with WP-CLI on
	 * a site that has no deploy pipeline. Empty means the feature is off and
	 * every delivery answer says so, rather than pretending "no events".
	 *
	 * @return string
	 */
	private static function sendgrid_pubkey() {
		if ( defined( 'JB_HEALTH_SENDGRID_PUBKEY' ) && JB_HEALTH_SENDGRID_PUBKEY ) {
			return trim( (string) JB_HEALTH_SENDGRID_PUBKEY );
		}
		// Bedrock loads .env with Dotenv; depending on the template's vintage the
		// values land in putenv(), $_ENV or $_SERVER — check all three, so the
		// deploy pipeline's `PROD_JB_HEALTH_SENDGRID_PUBKEY` repo variable works
		// on every site without a code change.
		foreach ( array( getenv( 'JB_HEALTH_SENDGRID_PUBKEY' ), isset( $_ENV['JB_HEALTH_SENDGRID_PUBKEY'] ) ? $_ENV['JB_HEALTH_SENDGRID_PUBKEY'] : null, isset( $_SERVER['JB_HEALTH_SENDGRID_PUBKEY'] ) ? $_SERVER['JB_HEALTH_SENDGRID_PUBKEY'] : null ) as $env ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( is_string( $env ) && '' !== trim( $env ) ) {
				return trim( $env );
			}
		}
		$opt = get_option( 'jb_health_sendgrid_pubkey' );
		return is_string( $opt ) ? trim( $opt ) : '';
	}

	/** Name of the events table. */
	private static function mail_events_table() {
		global $wpdb;
		return $wpdb->prefix . 'jb_health_mail_events';
	}

	/**
	 * POST /wp-json/jb-health/v1/mail-events — receive SendGrid's Event Webhook.
	 *
	 * Verification is SendGrid's signed-webhook scheme: an ECDSA/SHA-256
	 * signature over `timestamp . body`, checked against the subuser's public
	 * key. Nothing is parsed until the signature holds, and an unconfigured
	 * site answers 403 so a misdirected webhook is loud in SendGrid's own
	 * activity feed rather than silently absorbed.
	 *
	 * Stored: recipient, event, timestamp, the provider's reason. Never a
	 * subject, never a body — this is a delivery ledger, not a mail archive,
	 * and it keeps seven days.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public static function handle_mail_events( $request ) {
		$pub = self::sendgrid_pubkey();
		if ( '' === $pub ) {
			return new WP_REST_Response(
				array(
					'ok'      => false,
					'code'    => 'jb_health_webhook_unconfigured',
					'message' => 'this site has no SendGrid Event Webhook verification key (JB_HEALTH_SENDGRID_PUBKEY)',
				),
				403
			);
		}

		$body = (string) $request->get_body();
		if ( strlen( $body ) > 2 * 1024 * 1024 ) {
			return new WP_REST_Response( array( 'ok' => false, 'code' => 'jb_health_webhook_too_large' ), 413 );
		}

		$signature = (string) $request->get_header( 'X-Twilio-Email-Event-Webhook-Signature' );
		$timestamp = (string) $request->get_header( 'X-Twilio-Email-Event-Webhook-Timestamp' );

		if ( ! self::verify_sendgrid_signature( $pub, $timestamp, $body, $signature ) ) {
			return new WP_REST_Response(
				array(
					'ok'      => false,
					'code'    => 'jb_health_webhook_signature',
					'message' => 'the request is not signed by the configured SendGrid Event Webhook key',
				),
				401
			);
		}

		$events = json_decode( $body, true );
		if ( ! is_array( $events ) ) {
			return new WP_REST_Response( array( 'ok' => false, 'code' => 'jb_health_webhook_body' ), 400 );
		}

		$stored = self::store_mail_events( $events );

		$response = new WP_REST_Response(
			array(
				'ok'       => true,
				'received' => count( $events ),
				'stored'   => $stored,
			),
			200
		);
		$response->header( 'Cache-Control', 'no-store, private' );
		return $response;
	}

	/**
	 * SendGrid's signed Event Webhook: ECDSA (P-256) / SHA-256 over
	 * `timestamp . payload`, public key as base64 DER.
	 *
	 * The timestamp header is Unix seconds for THIS request (a retry is
	 * re-signed), so a 24h tolerance covers SendGrid's own retry window while
	 * refusing an ancient capture. Replaying a captured request can only
	 * re-insert events that already exist (unique sg_event_id), so it changes
	 * nothing.
	 *
	 * @param string $pub_b64   Base64 DER public key.
	 * @param string $timestamp Header value.
	 * @param string $body      Raw request body.
	 * @param string $sig_b64   Base64 signature header.
	 * @return bool
	 */
	private static function verify_sendgrid_signature( $pub_b64, $timestamp, $body, $sig_b64 ) {
		if ( ! function_exists( 'openssl_verify' ) || '' === $timestamp || '' === $sig_b64 ) {
			return false;
		}
		if ( ! ctype_digit( $timestamp ) || abs( time() - (int) $timestamp ) > DAY_IN_SECONDS ) {
			return false;
		}
		$sig = base64_decode( $sig_b64, true );
		if ( false === $sig ) {
			return false;
		}
		$pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split( preg_replace( '/\s+/', '', $pub_b64 ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
		$key = openssl_pkey_get_public( $pem );
		if ( false === $key ) {
			return false;
		}
		return 1 === openssl_verify( $timestamp . $body, $sig, $key, OPENSSL_ALGO_SHA256 );
	}

	/** Create the events table on first use. */
	private static function ensure_mail_events_table() {
		global $wpdb;
		$table = self::mail_events_table();
		if ( self::table_exists( $table ) ) {
			return true;
		}
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
				id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
				sg_event_id varchar(120) NOT NULL,
				sg_message_id varchar(191) NULL,
				email varchar(191) NOT NULL,
				event varchar(32) NOT NULL,
				reason text NULL,
				event_ts int(11) unsigned NOT NULL,
				received_at datetime NOT NULL,
				PRIMARY KEY  (id),
				UNIQUE KEY sg_event_id (sg_event_id),
				KEY email_ts (email(100), event_ts),
				KEY event_ts (event_ts)
			) {$charset};"
		);
		return self::table_exists( $table );
	}

	/**
	 * Insert a batch of events, idempotently (sg_event_id is unique), and
	 * drop anything older than seven days.
	 *
	 * @param array $events Decoded webhook batch.
	 * @return int Rows actually inserted.
	 */
	private static function store_mail_events( array $events ) {
		global $wpdb;
		if ( ! self::ensure_mail_events_table() ) {
			return 0;
		}
		$table  = self::mail_events_table();
		$stored = 0;
		$seen   = 0;

		foreach ( $events as $e ) {
			if ( ++$seen > 2000 ) {
				break;
			}
			if ( ! is_array( $e ) ) {
				continue;
			}
			$email = isset( $e['email'] ) && is_string( $e['email'] ) ? strtolower( sanitize_email( $e['email'] ) ) : '';
			$event = isset( $e['event'] ) && is_string( $e['event'] ) ? substr( sanitize_key( $e['event'] ), 0, 32 ) : '';
			if ( '' === $email || '' === $event ) {
				continue;
			}
			$event_id = isset( $e['sg_event_id'] ) && is_scalar( $e['sg_event_id'] )
				? substr( (string) $e['sg_event_id'], 0, 120 )
				: md5( wp_json_encode( $e ) );

			// The provider's own words about a non-delivery: a bounce's `reason`,
			// a deferral's `response`. Kept as the sentence SendGrid wrote, because
			// this line is read by a client in a support report — the SMTP status
			// is appended only when the sentence does not already contain it, and
			// the event `type` only when nothing else said anything. Capped: an
			// SMTP transcript can be long.
			$reason = '';
			foreach ( array( 'reason', 'response' ) as $k ) {
				if ( '' === $reason && ! empty( $e[ $k ] ) && is_scalar( $e[ $k ] ) ) {
					$reason = trim( (string) $e[ $k ] );
				}
			}
			if ( ! empty( $e['status'] ) && is_scalar( $e['status'] ) ) {
				$status = trim( (string) $e['status'] );
				if ( '' === $reason ) {
					$reason = $status;
				} elseif ( false === strpos( $reason, $status ) ) {
					$reason .= ' (' . $status . ')';
				}
			}
			if ( '' === $reason && ! empty( $e['type'] ) && is_scalar( $e['type'] ) ) {
				$reason = trim( (string) $e['type'] );
			}

			// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name cannot be bound.
			$rows = $wpdb->query(
				$wpdb->prepare(
					"INSERT IGNORE INTO `{$table}` (sg_event_id, sg_message_id, email, event, reason, event_ts, received_at)
					 VALUES (%s, %s, %s, %s, %s, %d, %s)",
					$event_id,
					isset( $e['sg_message_id'] ) && is_scalar( $e['sg_message_id'] ) ? substr( (string) $e['sg_message_id'], 0, 191 ) : '',
					$email,
					$event,
					self::clip( $reason, 500 ),
					isset( $e['timestamp'] ) && is_numeric( $e['timestamp'] ) ? (int) $e['timestamp'] : time(),
					gmdate( 'Y-m-d H:i:s' )
				)
			);
			// phpcs:enable
			if ( $rows ) {
				++$stored;
			}
		}

		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare( "DELETE FROM `{$table}` WHERE event_ts < %d", time() - ( 7 * DAY_IN_SECONDS ) ) );

		return $stored;
	}

	/**
	 * What the provider reported about the notification(s) sent for ONE entry.
	 *
	 * Events carry the recipient, not the form or the entry, so the match is
	 * "an event for one of this form's notification recipients, from the
	 * moment Gravity Forms logged the send for this entry to thirty minutes
	 * after". The lower bound matters: a notification cannot be delivered
	 * before it was sent, and any look-back lets an EARLIER message to the
	 * same address stand in for this one — a fake pass (seen in testing with
	 * two runs 12 seconds apart). Two submissions to the same recipient in
	 * the same half hour can still share an event; the check submits once
	 * per form per run, so that is a corner, and it is documented as one.
	 * Status vocabulary, worst first:
	 * bounced · dropped · deferred · processed · pending (nothing yet) ·
	 * delivered; `summary` rolls the recipients up the same way.
	 *
	 * "delivered" means the RECIPIENT'S mail server accepted the message. It is
	 * one step further than the notification log (our server handed it over),
	 * and still not a promise about a spam folder.
	 *
	 * @param int   $form_id Gravity Forms form id.
	 * @param array $row     Entry row: id, date_created.
	 * @return array
	 */
	private static function entry_delivery( $form_id, array $row ) {
		global $wpdb;

		$out = array(
			'configured' => '' !== self::sendgrid_pubkey(),
			'checked'    => false,
			'reason'     => null,
			'summary'    => 'unknown',
			'window'     => array( 'before_s' => 0, 'after_s' => 1800 ),
			'recipients' => array(),
		);

		if ( ! $out['configured'] ) {
			$out['reason'] = 'this site has no SendGrid Event Webhook key (JB_HEALTH_SENDGRID_PUBKEY), so provider delivery events are not collected';
			return $out;
		}
		$table = self::mail_events_table();
		if ( ! self::table_exists( $table ) ) {
			$out['reason'] = 'no delivery events have been received yet — check the subuser’s Event Webhook URL points at /wp-json/jb-health/v1/mail-events';
			return $out;
		}

		$form  = GFAPI::get_form( $form_id );
		$entry = GFAPI::get_entry( (int) $row['id'] );
		if ( ! is_array( $form ) || is_wp_error( $entry ) || ! is_array( $entry ) ) {
			$out['reason'] = 'could not load the form or the entry to resolve its notification recipients';
			return $out;
		}

		$recipients = self::notification_recipients( $form, $entry );
		if ( empty( $recipients ) ) {
			$out['reason'] = 'none of the form’s active submission notifications has a resolvable recipient (routing rules are not resolved)';
			return $out;
		}

		$created = empty( $row['date_created'] ) ? time() : strtotime( $row['date_created'] . ' UTC' );

		// The floor is the moment Gravity Forms logged the FIRST notification
		// attempt for this entry — the send itself — falling back to the entry's
		// creation. No look-back: an event before the send belongs to an earlier
		// message to the same address, and counting it would be a fake pass.
		$floor = $created;
		$notes = $wpdb->prefix . 'gf_entry_notes';
		if ( self::table_exists( $notes ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
			$first_note = $wpdb->get_var( $wpdb->prepare( "SELECT MIN(date_created) FROM `{$notes}` WHERE entry_id = %d AND note_type = %s", (int) $row['id'], 'notification' ) );
			if ( $first_note ) {
				$floor = max( $floor, (int) strtotime( $first_note . ' UTC' ) );
			}
		}
		$from = $floor - $out['window']['before_s'];
		$to   = $floor + $out['window']['after_s'];
		$out['window']['from'] = gmdate( 'c', $from );

		$out['checked'] = true;
		$statuses       = array();

		foreach ( $recipients as $addr ) {
			// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name cannot be bound.
			$rows = $wpdb->get_results(
				$wpdb->prepare(
					"SELECT event, reason, event_ts FROM `{$table}` WHERE email = %s AND event_ts BETWEEN %d AND %d ORDER BY event_ts, id",
					$addr,
					$from,
					$to
				),
				ARRAY_A
			);
			// phpcs:enable

			$events = array();
			$names  = array();
			foreach ( (array) $rows as $r ) {
				$names[]  = $r['event'];
				$events[] = array(
					'event'  => $r['event'],
					'at'     => gmdate( 'c', (int) $r['event_ts'] ),
					'reason' => '' === (string) $r['reason'] ? null : $r['reason'],
				);
			}

			if ( in_array( 'bounce', $names, true ) ) {
				$status = 'bounced';
			} elseif ( in_array( 'dropped', $names, true ) ) {
				$status = 'dropped';
			} elseif ( in_array( 'delivered', $names, true ) ) {
				$status = 'delivered';
			} elseif ( in_array( 'deferred', $names, true ) ) {
				$status = 'deferred';
			} elseif ( in_array( 'processed', $names, true ) ) {
				$status = 'processed';
			} else {
				$status = 'pending';
			}
			$statuses[]          = $status;
			$out['recipients'][] = array(
				'to'     => $addr,
				'status' => $status,
				'events' => $events,
			);
		}

		if ( in_array( 'bounced', $statuses, true ) ) {
			$out['summary'] = 'bounced';
		} elseif ( in_array( 'dropped', $statuses, true ) ) {
			$out['summary'] = 'dropped';
		} elseif ( count( array_unique( $statuses ) ) === 1 && 'delivered' === $statuses[0] ) {
			$out['summary'] = 'delivered';
		} elseif ( in_array( 'delivered', $statuses, true ) ) {
			$out['summary'] = 'partial';
		} elseif ( in_array( 'deferred', $statuses, true ) ) {
			$out['summary'] = 'deferred';
		} elseif ( in_array( 'processed', $statuses, true ) ) {
			$out['summary'] = 'processed';
		} else {
			$out['summary'] = 'pending';
		}

		return $out;
	}

	/**
	 * The addresses a form's active submission notifications go to, for one
	 * entry, with merge tags resolved ({admin_email}, a field the visitor
	 * typed). Routing-type notifications are skipped rather than guessed.
	 *
	 * @param array $form  Gravity Forms form.
	 * @param array $entry Gravity Forms entry.
	 * @return string[] Lower-cased, de-duplicated addresses.
	 */
	private static function notification_recipients( array $form, array $entry ) {
		$out = array();
		if ( empty( $form['notifications'] ) || ! is_array( $form['notifications'] ) ) {
			return $out;
		}
		foreach ( $form['notifications'] as $n ) {
			if ( ! is_array( $n ) ) {
				continue;
			}
			if ( isset( $n['isActive'] ) && ! $n['isActive'] ) {
				continue;
			}
			if ( isset( $n['event'] ) && 'form_submission' !== $n['event'] ) {
				continue;
			}
			$to_type = isset( $n['toType'] ) ? (string) $n['toType'] : 'email';
			$raw     = '';
			if ( 'field' === $to_type ) {
				$field_id = isset( $n['toField'] ) ? (string) $n['toField'] : ( isset( $n['to'] ) ? (string) $n['to'] : '' );
				$raw      = '' === $field_id ? '' : (string) rgar( $entry, $field_id );
			} elseif ( 'routing' !== $to_type ) {
				$raw = isset( $n['to'] ) ? (string) $n['to'] : '';
			}
			if ( '' === $raw ) {
				continue;
			}
			if ( class_exists( 'GFCommon' ) && false !== strpos( $raw, '{' ) ) {
				$raw = GFCommon::replace_variables( $raw, $form, $entry, false, false, false, 'text' );
			}
			foreach ( preg_split( '/[,;]+/', $raw ) as $addr ) {
				$addr = strtolower( trim( $addr ) );
				if ( '' !== $addr && is_email( $addr ) ) {
					$out[ $addr ] = true;
				}
			}
		}
		return array_keys( $out );
	}

	/**
	 * Site-wide delivery outcome for the last 30 days, from the events table.
	 * Events carry the recipient, not the form, so this is the whole site's
	 * mail — the number that says "the client actually receives what this site
	 * sends", and the bounce that says which address is dead.
	 *
	 * @return array
	 */
	private static function mail_delivery_30d() {
		global $wpdb;

		$out = array(
			'webhook_configured' => '' !== self::sendgrid_pubkey(),
			'checked'            => false,
			'reason'             => null,
			'delivered'          => 0,
			'bounced'            => 0,
			'dropped'            => 0,
			'deferred'           => 0,
			'last_event_at'      => null,
			'last_bounce'        => null,
		);

		if ( ! $out['webhook_configured'] ) {
			$out['reason'] = 'no SendGrid Event Webhook key on this site (JB_HEALTH_SENDGRID_PUBKEY)';
			return $out;
		}
		$table = self::mail_events_table();
		if ( ! self::table_exists( $table ) ) {
			$out['reason'] = 'no delivery events received yet — check the subuser’s Event Webhook URL';
			return $out;
		}

		$d30 = time() - ( 30 * DAY_IN_SECONDS );

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name cannot be bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare( "SELECT event, COUNT(*) AS c, MAX(event_ts) AS last_ts FROM `{$table}` WHERE event_ts >= %d GROUP BY event", $d30 ),
			ARRAY_A
		);
		// phpcs:enable
		if ( ! is_array( $rows ) ) {
			$out['reason'] = 'the delivery events table was not readable';
			return $out;
		}

		$out['checked'] = true;
		$last           = 0;
		$map            = array(
			'delivered' => 'delivered',
			'bounce'    => 'bounced',
			'dropped'   => 'dropped',
			'deferred'  => 'deferred',
		);
		foreach ( $rows as $r ) {
			if ( isset( $map[ $r['event'] ] ) ) {
				$out[ $map[ $r['event'] ] ] = (int) $r['c'];
			}
			$last = max( $last, (int) $r['last_ts'] );
		}
		$out['last_event_at'] = $last ? gmdate( 'c', $last ) : null;

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name cannot be bound.
		$b = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT email, event, reason, event_ts FROM `{$table}` WHERE event IN ('bounce','dropped') AND event_ts >= %d ORDER BY event_ts DESC, id DESC LIMIT 1",
				$d30
			),
			ARRAY_A
		);
		// phpcs:enable
		if ( $b ) {
			$out['last_bounce'] = array(
				'to'     => self::mask_email( $b['email'] ),
				'event'  => $b['event'],
				'reason' => '' === (string) $b['reason'] ? null : $b['reason'],
				'at'     => gmdate( 'c', (int) $b['event_ts'] ),
			);
		}

		return $out;
	}

	/** j***@example.com — enough to recognise an address, not enough to harvest it. */
	private static function mask_email( $email ) {
		$email = (string) $email;
		$at    = strpos( $email, '@' );
		if ( false === $at ) {
			return $email;
		}
		return substr( $email, 0, 1 ) . '***' . substr( $email, $at );
	}

	// ----------------------------------------------------------------- //
	// Entry lookup
	// ----------------------------------------------------------------- //

	/**
	 * Answer one question, and only one: did the submission carrying THIS run
	 * reference land, and what did Gravity Forms record about its notifications?
	 *
	 * form-check submits a form from outside the server and then has to prove
	 * two things the browser cannot show it — that the entry was actually
	 * stored, and that WordPress actually handed the notification to a mail
	 * server. On a local site it reads the database directly. On staging, live
	 * or a Loop runner it has neither database nor WP-CLI, so it asks here.
	 *
	 * The answer is 200 whether or not the entry exists: "no entry carrying
	 * that stamp" is a legitimate result of the check rather than a transport
	 * failure, and squashing it into a 404 would make it indistinguishable
	 * from this route being absent on a site still running 1.4.0.
	 *
	 * @param WP_REST_Request $request Request.
	 * @return WP_REST_Response
	 */
	public static function handle_entry_lookup( $request ) {
		$form  = (int) $request->get_param( 'form' );
		$stamp = (string) $request->get_param( 'stamp' );
		$hours = (int) $request->get_param( 'hours' );

		$payload = array(
			'ok'             => true,
			'schema_version' => JB_HEALTH_SCHEMA,
			'plugin_version' => JB_HEALTH_VERSION,
			'generated_at'   => gmdate( 'c' ),
			'site'           => self::site_info(),
			// Echoed back so a queued or retried call can never be read against
			// the wrong question.
			'query'          => array(
				'form'  => $form,
				'stamp' => $stamp,
				'hours' => $hours,
			),
		);

		$response = new WP_REST_Response( array_merge( $payload, self::entry_lookup( $form, $stamp, $hours ) ), 200 );
		// Per-site operational data, exactly like /report — never let a proxy
		// or CDN hold it.
		$response->header( 'Cache-Control', 'no-store, private' );
		return $response;
	}

	/**
	 * A form id, as an id — not "12abc", which absint() would quietly accept as 12.
	 *
	 * @param mixed $value Raw query value.
	 * @return true|WP_Error
	 */
	public static function validate_form_id( $value ) {
		if ( is_scalar( $value ) && preg_match( '/^[0-9]+$/D', (string) $value ) && (int) $value >= 1 ) {
			return true;
		}
		return new WP_Error( 'jb_health_bad_form', 'form must be a positive integer.', array( 'status' => 400 ) );
	}

	/**
	 * The stamp format IS the security model of this route.
	 *
	 * form-check writes a run reference — JBFC-<8 hex>, suffixed -F<form id>
	 * for the per-form variant — into a name/text/textarea field before it
	 * submits, and that reference is the only thing this endpoint will ever
	 * match on. Accepting an arbitrary needle would turn a read-only reporting
	 * key into "search every entry on this site for string X", which is a PII
	 * exfiltration tool wearing a health-check badge. A caller can only ask
	 * about a reference it wrote itself.
	 *
	 * The D modifier is not decoration: without it PHP's `$` also matches
	 * before a trailing newline, so "JBFC-DEADBEEF\n" would pass a pattern
	 * that reads as though it could not.
	 *
	 * @param mixed $value Raw query value.
	 * @return true|WP_Error
	 */
	public static function validate_stamp( $value ) {
		if ( is_string( $value ) && preg_match( '/^JBFC-[A-F0-9]{8}(?:-F[0-9]{1,6})?$/D', $value ) ) {
			return true;
		}
		return new WP_Error(
			'jb_health_bad_stamp',
			'stamp must be a form-check run reference: JBFC-XXXXXXXX, or JBFC-XXXXXXXX-F<form id>.',
			array( 'status' => 400 )
		);
	}

	/**
	 * The window is a bound, not a preference. `meta_value` carries no index a
	 * leading-wildcard LIKE can use, so an unbounded scan across an entry meta
	 * table with years of rows in it is a denial of service dressed as a query
	 * string. One week is already generous for "did the submission I just made
	 * land".
	 *
	 * @param mixed $value Raw query value.
	 * @return true|WP_Error
	 */
	public static function validate_hours( $value ) {
		if ( is_scalar( $value ) && preg_match( '/^[0-9]+$/D', (string) $value ) ) {
			$hours = (int) $value;
			if ( $hours >= 1 && $hours <= 168 ) {
				return true;
			}
		}
		return new WP_Error( 'jb_health_bad_hours', 'hours must be an integer between 1 and 168.', array( 'status' => 400 ) );
	}

	/**
	 * Find the entry carrying $stamp, then read what Gravity Forms recorded
	 * about the notifications it tried to send for it.
	 *
	 * Two deliberate choices:
	 *
	 *   - No `status` filter. A test submission that landed in spam or trash is
	 *     a FINDING — the form works, but the entry is being thrown away — so
	 *     the status is reported rather than used to hide the row.
	 *     `entry_stats()` filters to active because it is counting genuine
	 *     volume; this is looking for one specific row we know we created.
	 *   - The date window narrows before the LIKE does, which is what keeps
	 *     this cheap on a site with years of entries.
	 *
	 * Nothing the visitor typed is ever returned: only ids, the entry status,
	 * timestamps, and the meta_key of the field the stamp was found in.
	 *
	 * @param int    $form_id Gravity Forms form id.
	 * @param string $stamp   Validated form-check run reference.
	 * @param int    $hours   How far back to look.
	 * @return array
	 */
	private static function entry_lookup( $form_id, $stamp, $hours ) {
		global $wpdb;

		$out = array(
			'engine'        => null,
			'found'         => false,
			'entry'         => null,
			'notifications' => self::no_notification_notes( null ),
			// What the sending provider reported about the notification(s) for
			// THIS entry — delivered / bounced / deferred per recipient (1.7.0).
			// null until the entry is found.
			'delivery'      => null,
			'reason'        => null,
		);

		if ( ! class_exists( 'GFAPI' ) || ! class_exists( 'GFCommon' ) ) {
			$out['reason']                  = 'Gravity Forms is not active on this site; no other form plugin is supported yet';
			$out['notifications']['reason'] = $out['reason'];
			return $out;
		}

		$entries = $wpdb->prefix . 'gf_entry';
		$meta    = $wpdb->prefix . 'gf_entry_meta';
		if ( ! self::table_exists( $entries ) || ! self::table_exists( $meta ) ) {
			$out['reason']                  = 'the Gravity Forms entry tables were not readable';
			$out['notifications']['reason'] = $out['reason'];
			return $out;
		}

		$out['engine'] = 'gravityforms';

		// Gravity Forms stores date_created in UTC, so the bound is built in UTC too.
		$since = gmdate( 'Y-m-d H:i:s', time() - ( $hours * HOUR_IN_SECONDS ) );
		$like  = '%' . $wpdb->esc_like( $stamp ) . '%';

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table names cannot be bound.
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT e.id, e.form_id, e.status, e.date_created, m.meta_key
				 FROM `{$entries}` e
				 JOIN `{$meta}` m ON m.entry_id = e.id
				 WHERE e.form_id = %d
				   AND e.date_created >= %s
				   AND m.meta_value LIKE %s
				 ORDER BY e.id DESC
				 LIMIT 1",
				$form_id,
				$since,
				$like
			),
			ARRAY_A
		);
		// phpcs:enable

		if ( ! $row ) {
			$out['reason']                  = sprintf(
				'no entry carrying that stamp on form %d in the last %dh',
				$form_id,
				$hours
			);
			$out['notifications']['reason'] = $out['reason'];
			return $out;
		}

		$out['found'] = true;
		$out['entry'] = array(
			'id'            => (int) $row['id'],
			'form_id'       => (int) $row['form_id'],
			'status'        => isset( $row['status'] ) ? (string) $row['status'] : null,
			'created_at'    => empty( $row['date_created'] ) ? null : gmdate( 'c', strtotime( $row['date_created'] . ' UTC' ) ),
			// The FIELD the stamp was found in, never its contents.
			'matched_field' => isset( $row['meta_key'] ) ? (string) $row['meta_key'] : null,
		);
		$out['notifications'] = self::notification_notes( (int) $row['id'] );
		$out['delivery']      = self::entry_delivery( (int) $row['form_id'], $row );

		return $out;
	}

	/**
	 * What Gravity Forms recorded about each notification for one entry.
	 *
	 * GF writes one note per attempt from
	 * GFFormsModel::add_notification_note() — present since GF 2.4.14 — with
	 * note_type 'notification' and sub_type 'success' or 'error'. The success
	 * text is GF's own "WordPress successfully passed the notification email to
	 * the sending server"; the error text carries the underlying reason (an
	 * invalid TO address, or whatever PHPMailer's ErrorInfo said).
	 *
	 * That wording is also the honest limit of the check: it proves the mail
	 * was ACCEPTED by the sending server, never that it reached an inbox. It is
	 * still the difference between "the form quietly mails nobody" and "the
	 * mail left the building".
	 *
	 * The note text is GF's own system message rather than visitor input, so
	 * returning it discloses nothing about the submitter — it is capped at 500
	 * characters because an SMTP error can carry an entire server transcript.
	 *
	 * @param int $entry_id Entry to read notes for.
	 * @return array
	 */
	private static function notification_notes( $entry_id ) {
		global $wpdb;

		$out   = self::no_notification_notes( null );
		$table = $wpdb->prefix . 'gf_entry_notes';

		if ( ! self::table_exists( $table ) ) {
			$out['reason'] = 'the Gravity Forms entry notes table is not present on this site';
			return $out;
		}

		// Schemas older than Gravity Forms 2.3 have no sub_type column, and a
		// failed query returns an empty result set indistinguishable from "no
		// notes were written" — which would report a silent mail failure as a
		// clean zero. Say so instead of counting nothing.
		if ( ! self::column_exists( $table, 'sub_type' ) ) {
			$out['reason'] = 'the entry notes table has no sub_type column (Gravity Forms schema older than 2.3), so notification results cannot be classified';
			return $out;
		}

		// phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name cannot be bound.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT sub_type, value, date_created
				 FROM `{$table}`
				 WHERE entry_id = %d AND note_type = %s
				 ORDER BY id",
				$entry_id,
				'notification'
			),
			ARRAY_A
		);
		// phpcs:enable

		if ( ! is_array( $rows ) ) {
			$out['reason'] = 'the Gravity Forms entry notes table was not readable';
			return $out;
		}

		$out['checked'] = true;

		foreach ( $rows as $note ) {
			$sub = isset( $note['sub_type'] ) ? (string) $note['sub_type'] : '';

			if ( 'success' === $sub ) {
				++$out['success'];
			} elseif ( 'error' === $sub ) {
				++$out['errors'];
			}

			$out['items'][] = array(
				// An add-on can write a sub_type of its own, so success + errors
				// does not always add up to the number of items.
				'sub_type'   => '' === $sub ? null : $sub,
				'message'    => self::clip( isset( $note['value'] ) ? $note['value'] : '', 500 ),
				'created_at' => empty( $note['date_created'] ) ? null : gmdate( 'c', strtotime( $note['date_created'] . ' UTC' ) ),
			);
		}

		return $out;
	}

	/**
	 * The "not read" shape for notifications.
	 *
	 * Same keys whichever way it goes, so the caller never has to test for a
	 * missing counter: `checked` false alongside a reason is the difference,
	 * not an absent field. A zero that means "not measured" is exactly the
	 * thing this plugin refuses to emit.
	 *
	 * @param string|null $reason Why the notes were not read.
	 * @return array
	 */
	private static function no_notification_notes( $reason ) {
		return array(
			'checked' => false,
			'reason'  => $reason,
			'success' => 0,
			'errors'  => 0,
			'items'   => array(),
		);
	}

	/**
	 * Cap a note at $limit characters, marking the cut so a truncated SMTP
	 * transcript can never be read as the whole of what the server said.
	 *
	 * @param string $text  Note text.
	 * @param int    $limit Maximum length of the returned string.
	 * @return string
	 */
	private static function clip( $text, $limit ) {
		$text = trim( (string) $text );
		return mb_strlen( $text ) > $limit ? mb_substr( $text, 0, $limit - 1 ) . '…' : $text;
	}

	/** Does a table exist? Guards every raw-table read above. */
	private static function table_exists( $table ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		return (bool) $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $table ) );
	}

	/**
	 * Does a column exist? Guards a read that a missing column would answer
	 * with a silent empty set rather than an error.
	 */
	private static function column_exists( $table, $column ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery
		return (bool) $wpdb->get_var( $wpdb->prepare( "SHOW COLUMNS FROM `{$table}` LIKE %s", $column ) );
	}
}

JB_Site_Health::init();
