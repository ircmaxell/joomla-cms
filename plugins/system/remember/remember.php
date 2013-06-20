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
				$parts = explode(':', $cookieVal, 3);

				// If the cookie is in the valid format, hand off the remaining checks to the cookie auth plugin.
				if (count($parts) === 3)
				{
					list ($userName, $token, $mac) = $parts;
 					$app = JFactory::getApplication();
					if (JCrypt::timingSafeCompare(hash_hmac('sha256', $token, $app->getCfg('secret')), $mac)) {
						// Use the token as the password, only if the authentication hash is successful
						$credentials = array(
							'username' => $userName,
							'password' => $token
						);
	
						return $app->login($credentials, array('silent' => true));
					}
				}
			}
		}
	}
}
