<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  Authentication.joomla
 *
 * @copyright   Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

/**
 * Joomla Authentication plugin
 *
 * @package     Joomla.Plugin
 * @subpackage  Authentication.joomla
 * @since       1.5
 */
class PlgAuthenticationCookie extends JPlugin
{
	/**
	 * This method should handle any authentication and report back to the subject.
	 *
	 * Remember here that $credentials is not your standard format.
	 * Since this is the cookie auth, it's structured as the following:
	 *
	 * $credentials = array(
	 *     'username' => $user_id,
	 *     'password' => $token
	 * );
	 *
	 * @access	public
	 * @param   array  Array holding the user credentials
	 * @param   array  Array of extra options
	 * @param   object	Authentication response object
	 * @return  boolean
	 * @since 1.5
	 */
	public function onUserAuthenticate($credentials, $options, &$response)
	{
		$app = JFactory::getApplication();

		$response->type = 'Cookie';
		// Joomla does not like blank passwords
		if (empty($credentials['password']))
		{
			$response->status = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_EMPTY_PASS_NOT_ALLOWED');
			return false;
		}

		$loginToken = implode(':', $credentials);

		// Get a database object
		$db		= JFactory::getDbo();
		$query	= $db->getQuery(true)
			->select('id, loginToken')
			->from('#__users')
			->where('loginToken = ' . $db->quote($loginToken));

		$result = $db->setQuery($query)->loadObject();

		if ($result)
		{
			// If the found row matches the user_id in the cookie, we have success.
			if ($result->id === $credentials['username'])
			{
				$response->status = JAuthentication::STATUS_SUCCESS;
				$response->error_message = '';
			}
		}
		else
		{
			// Expire the invalid cookie.
			$cookie_domain = $app->getCfg('cookie_domain', '');
			$cookie_path = $app->getCfg('cookie_path', '/');
			$app->input->cookie->set(
				JApplication::getHash('JLOGIN_REMEMBER'), false, time() - 86400,
				$cookie_path, $cookie_domain
			);

			$response->status = JAuthentication::STATUS_FAILURE;
			$response->error_message = JText::_('JGLOBAL_AUTH_NO_USER');
		}
	}
}
