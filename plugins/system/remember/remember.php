<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  System.remember
 *
 * @copyright   Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

/**
 * Joomla! System Remember Me Plugin
 *
 * @package     Joomla.Plugin
 * @subpackage  System.remember
 * @since       1.5
 */
class PlgSystemRemember extends JPlugin
{
	public function onAfterInitialise()
	{
		$app = JFactory::getApplication();

		// No remember me for admin
		if ($app->isAdmin())
		{
			return;
		}

		$user = JFactory::getUser();
		if ($user->get('guest'))
		{
			// The login cookie uses a hashed value for the cookie name.
			$cookieName = JApplication::getHash('JLOGIN_REMEMBER');

			// The login cookie is in "user_id:token" format.
			$cookieVal = $app->input->cookie->getString($cookieName);

			// A cookie was found, let's try it out.
			if ($cookieVal !== null)
			{
				$parts = explode(':', $cookieVal, 2);

				// If the cookie is in the valid format, hand off the remaining checks to the cookie auth plugin.
				if (count($parts) === 2 && is_numeric($parts[0]))
				{
					// Use the user_id as the username and the token as the password.
					$credentials = array(
						'username' => $parts[0],
						'password' => $parts[1]
					);

					return $app->login($credentials, array('silent' => true));
				}
			}
		}
	}

	/**
	 * Generate a new login cookie.
	 *
	 * @param  array  $user     Holds the user data
	 * @param  array  $options  Array holding options (remember, autoregister, group)
	 */
	public function onUserLogin($user, $options = array())
	{
		$app = JFactory::getApplication();

		// Let's create a new login cookie.
		$cookieName = JApplication::getHash('JLOGIN_REMEMBER');

		// Generate a secure 256 bit random token string.
		$token = JCrypt::genRandomBytes(32);

		$cookieVal = $user->id . ':' . $token;

		// Get the number of days to stay logged in. Defaults to 30.
		$loginTokenExpire = (int) $this->params->get('login_token_expire', 30);
		$cookieExpire = time() + (3600 * 24 * $loginTokenExpire);
		$cookiePath = $app->getCfg('cookie_path', '/');
		$cookieDomain = $app->getCfg('cookie_domain', '');
		$isSsl = $app->isSSLConnection();

		// The final true is to make the cookie available ONLY have http. Reduces XSS vulnerability.
		$app->input->cookie->set($cookieName, $cookieVal, $cookieExpire, $cookiePath, $cookieDomain, $isSsl, true);

		return true;
	}
}
