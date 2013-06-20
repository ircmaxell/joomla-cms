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
				$privateKey = JApplication::getHash(@$_SERVER['HTTP_USER_AGENT']);
				$key = new JCryptKey('simple', $privateKey, $privateKey);
				$crypt = new JCrypt(new JCryptCipherSimple, $key);

				// Decrypt the token to get the username.
				$loginToken = $crypt->decrypt($cookieVal);

				$parts = explode(':', $loginToken, 2);

				// If the cookie is in the valid format, hand off the remaining checks to the cookie auth plugin.
				if (count($parts) === 2)
				{
					// Use the fully encrypted token as the password.
					$credentials = array(
						'username' => $parts[0],
						'password' => $cookieVal
					);

					return $app->login($credentials, array('silent' => true));
				}
			}
		}
	}
}
