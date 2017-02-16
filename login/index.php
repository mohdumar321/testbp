<?php
/**
 * Login-Script for internal BP users.
 *
 * Last			$Author: oktakv $
 *
 * @package    sys
 * @subpackage core
 * @author     Michael Galka <m.galka@smf.de>
 * @version    <b>$Revision: 17294 $</b> $Date: 2015-11-17 11:59:03 +0100 (Tue, 17 Nov 2015) $
 * @copyright  (C) 2008 BP Oil Marketing GmbH
 */

/**
 * Require Main
 */
require "RosiMain.class.php";

RosiMain::initialize(RosiMain::PURPOSE_LOGIN);
$config = \rosi\system\Configuration::get();
$translator = new Translator();

$isRobotLogin = strpos($_SERVER['PHP_SELF'], 'robot_login.php') !== false;

if($isRobotLogin && $config->getParameter('allow_robot_login') !== 'Yes') {
	exit("<h3>Access denied.</h3>");
}

// Get the Login Name for the current User
if($isRobotLogin) {
	$userLogin = 'onebp-robot';
} elseif(($userLogin = Login::getUserLogin()) === false) {
	showError($translator->getText('Internal_Login_Not_Avail'));
}

// Initialize remaining framework including session handling
RosiMain::initialize(RosiMain::PURPOSE_POSTLOGIN);

if($isRobotLogin) {
	$_SESSION['Login']['isRobotLogin'] = true;
}

// Set User-Entry to NTLM-Login. Important at least for Logoff Page, where User
// is able to do a Re-Login which must redirect to this page then.
$_SESSION['Login']['userEntry'] = 'intranet_coe';

// Has the User a '-remote-' Login Name? This means, he/she dialed in via VPN, but this Name is
// just an Addition to a standard Login Name. So we need to transform to the standard Name.
if(substr($userLogin, 0, 8) === '-remote-') {
	$userLogin = substr($userLogin, 8);
}

try {
	$user = \rosi\system\User::getByLoginName($userLogin);
} catch(RosiException $e) {
	$user = new \rosi\system\User();
	$user->setLoginName($userLogin);
}

if(is_null($user->getId())
|| ($user->getName() === 'Benutzer' && $user->getLoginName() === $user->getName())) {
	// Not a known User, or a User with yet just default/dummy data.
	if($config->getParameter('login_benutzer_identify') !== '1') {
		// Do not request User Data from Active Directory or manually be User Form.
		// This means: Users with yet just default/dummy data may pass. But: Unknown Users get a Denial.
		if(is_null($user->getId())) {
			showError($translator->getText('Login_Denied'));
		}
	}

	if(!$config->getParameter('get_userdata_from_ads')) {
		Login::getUserDataByForm($user);
	} else {
		// User-Data Retrieval from Active Directory should be used.
		// But: This can be limited to specific countries in the following Parameters:
		// ads_allowed_countries: Comma-separated list of country codes
		// ads_allowed_country_prefix: Comma-separated list of phone prefixes

		// Initially, query ADS to get the User's country and phone for further checks.
		if(!Login::getUserDataByAds($user, $userLogin)) {
			// ADS-Query was faulty, Error Message is already in Logfile.
			// Redirect to Main Login Page.
			showError($translator->getText('Login_AD_fault'));
		}

		$allowedCountries = preg_split(
			'(,)', $config->getParameter('ads_allowed_countries'),
			-1, PREG_SPLIT_NO_EMPTY);
		$allowedPrefixes = preg_split(
			'(,)', $config->getParameter('ads_allowed_country_prefix'),
			-1, PREG_SPLIT_NO_EMPTY);

		if($allowedCountries || $allowedPrefixes) {
			$countryFound = $user->getCountry()
				&& in_array($user->getCountry()->getIsoAlpha2(), $allowedCountries);
			$prefixFound = false;
			foreach($allowedPrefixes as $allowedPrefix) {
				if(strpos($user->getPhone(), $allowedPrefix) === 0) {
					$prefixFound = true;
					break;
				}
			}

			if(!$countryFound && !$prefixFound) {
				Login::getUserDataByForm($user);
			}
		}
	}

	$isNewUser = is_null($user->getId());
	if($user->isValid()) {
		$user->save();
	} else {
		throw new RosiException('INVALID_DATA', $_SERVER['SCRIPT_NAME'], serialize($user->getValidationErrorList()), 'User Create');
	}

	if($isNewUser) {
		// New Users created by NTLM Login Script are assigned to User Group 'All'
		// by default.
		$user->addUserGroup(new \rosi\system\UserGroup('ALL'));
	}

	if($isNewUser
	&& $config->getParameter('preset_favorites')) {
		UserLink::copyAll(
			new \rosi\system\User($config->getParameter('preset_favorites')),
			$user);
		UserExternalLink::copyAll(
			new \rosi\system\User($config->getParameter('preset_favorites')),
			$user);
	}

	if($isNewUser
	&& $config->getParameter('notify_new_user')) {
		require_once 'class.mail.php';

		$mail = new Mail;
		$mail->From('rissup@bp.com');
		if(\rosi\system\Configuration::isLiveSystem()) {
			$mail->To(explode(';', $config->getParameter('BUSINESS_TEAM_EMAIL')));
		} else {
			$mail->To(explode(';', $config->getParameter('sys_webmaster_email')));
		}
		$mail->Subject(sprintf(
			'New user %s on Instance: %s',
			$user->getLoginName(),
			$config->getParameter('instance')));

		$mailBody = array();
		$mailBody[] = sprintf('Name: %s, %s', $user->getLastname(),
			$user->getFirstname());
		$mailBody[] = sprintf('Phone: %s', $user->getPhone());
		$mailBody[] = sprintf('Email: %s', $user->getEmail());
		$mailBody[] = sprintf('Department: %s', $user->getDepartmentSap());
		$mail->Body(implode('<br>', $mailBody));

		$mail->Send();
	}
}

$isNewUser 	= is_null($user->getId());
$firstLogin = $user->getLastSuccessfulLogin()? false: true;
if(($isNewUser || $firstLogin) && $config->getParameter('notify_users_first_login')) {
	Login::sendEmailOnFirstLogin($user);		
}

// Set Site and Dealer, if User belongs to just one Site.
$sql = "
	SELECT	COUNT(*)
	FROM		user_tables
	WHERE		table_name IN ('BP_SITE', 'BP_DEALER')
";
if(Database::get()->CacheGetOne(60*60*24, $sql) == 2) {
	if(is_numeric($user->getSiteId())) {
		if($user->getSiteList()->containsId($user->getSiteId())) {
			$site = new Site($user->getSiteId());
			Site::setSelected($site);
			$dealer = $site->getDealer();
			if(!$dealer) {
				showError($translator->getText('Login_Inconsistent_Data'));
				exit;
			}
			Dealer::setSelected($dealer);
		}
	} else {
		$userSiteList = new SiteList(0, 2);
		$userSiteList->loadActiveByUser($user);
		if(count($userSiteList) === 1) {
			$userSiteList->rewind();
			Site::setSelected($userSiteList->current());
	
			$dealer = $userSiteList->current()->getDealer();
			if(!$dealer) {
				showError($translator->getText('Login_Inconsistent_Data'));
				exit;
			}
			Dealer::setSelected($dealer);
		}
	}
}

// Deny access for disabled users (also for users with disabled parents).
if(!Login::isUserAndParentsActive($user)) {
	if($_SESSION['Login']['userEntry'] == 'intranet_coe' && \rosi\system\Configuration::getCurrentSchema() == 'intogy') {
		$_SESSION['Login']['disabledUser'] = 1;
	}
	showError($translator->getText('Login_Wrong_ID_PW'));
	exit;
}

// Login Successful.
\rosi\system\User::setCurrent($user);

// Add all the Values to the Session which are mandatory for old PHP4 Framework.
Login::addPhp4SessionVars();

// Set Prior Login Date to Last Login Date. Set Last Login Date to now.
$dt = $user->getLastSuccessfulLogin();
$user->setPriorSuccessfulLogin($dt? $dt: new DateTime());

// No Last Login == 1 --> Login Alias
if($_GET['no_last_login'] !== '1') {
	$user->setLastSuccessfulLogin(new DateTime());
} else {
	\rosi\system\Cache::drop("User-" . $user->getId() . "*");
	// Update Session Key in Login-Alias-Log created by login_alias.php
	$sql = "
		UPDATE	ris_user_loginalias
		SET			sessionid = :sessionId
		WHERE		alias_id = :userId
				AND	crt_date_time = (
							SELECT	MAX(crt_date_time)
							FROM		ris_user_loginalias
							WHERE		alias_id = :userId
						)
	";
	Database::get()->Execute($sql, array(
		'userId'		=> $user->getId()
	,	'sessionId'	=> session_id()
	));
	$_SESSION['LOGIN_ALIAS_TEXT'] = Database::get()->getOne("select '\"'||user_name||'\" as \"'||alias_name||'\"' from ris_user_loginalias where sessionid=:sessionId", array('sessionId'=>session_id()));
}

// Fix for Users without Language.
if(!strlen($user->getLanguage())) {
	$user->setLanguage(\rosi\system\Configuration::getDefaultLanguage());
	$user->save();
} else {
	$user->saveLoginData();
}

Logger::getLogger("Login")->debug(new \rosi\system\RosiLogMessage(
	sprintf("Successful login for user %s[%d] in session '%s' from IP %s",
		$user->getLoginName(),
		$user->getId(),
		session_id(),
		\rosi\system\Configuration::getRemoteIp()),
	sprintf("Successful login for user %s[%d]", $user->getLoginName(), $user->getId()),
	array('login_method' => 'NTLM')));

// Write Logfile-Table Entry
$sql = "
	INSERT INTO logfile (userid, datetime, session_id)
	VALUES  (:userId, :dateTime, :sessionId)
";
Database::get()->Execute($sql, array(
	'userId'		=> $user->getId()
,	'dateTime'	=> date('Y-m-d H:i:s')
,	'sessionId'	=> session_id()
));

// If we got a URL as CGI-Parameter, this means we got a direct link to an application.
if(array_key_exists('url', $_GET)) {
	// Clear Query-String from CGI-Parameters "sid" and "ti" which come from NTLM
	// Login. These would damage the destination URL in the QUERY_STRING.
	// The sid should be url-encoded before removal (added 16-Jul-2009)
	$queryString = preg_replace("(&?sid=".urlencode($_GET['sid']).")", '', $_SERVER['QUERY_STRING']);
	$queryString = preg_replace("(&?ti={$_GET['ti']})", '', $queryString);
	header("Location: " . preg_replace('(^url=)', '', $queryString));
	exit;
}

$startPage = \Login::getUserStartPage($config);

header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
header("Cache-Control: no-cache, must-revalidate");
header("Pragma: no-cache");
header("Location: {$startPage}");
exit;

/**
 * Show an Error Message.
 *
 * Redirect to the Main index Page (from manual login process) and display an Error Text.
 * Execution stops when this function is being called.
 *
 * @param  string  $errorText  The Error Text.
 * @return void.
 */
function showError($errorText)
{
	if(isset($_SESSION['Login']['disabledUser']) && $_SESSION['Login']['disabledUser'] == 1) {
		header("Location: /main/index.php?meldung={$errorText}&disabled=1");
	} else {
		header("Location: /main/index.php?meldung={$errorText}");
	}

	exit;
}
