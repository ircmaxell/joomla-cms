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

		// Get a database object
		$db		= JFactory::getDbo();
		$query	= $db->getQuery(true)
			->select('loginToken')
			->from('#__users')
			->where('username = ' . $db->quote($credentials['username']));

		$result = $db->setQuery($query)->loadObject();

		// The password here is really the loginToken.
		$loginToken = $credentials['password'];

		if ($result && $this->timingSafeCompare($result->loginToken, $loginToken))
		{
			$response->status = JAuthentication::STATUS_SUCCESS;
			$response->error_message = '';
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

	/**
	 * A timing safe comparison method. This defeats hacking
	 * attempts that use timing based attack vectors.
	 *
	 * @param   string  $known    A known string to check against.
	 * @param   string  $unknown  An unknown string to check.
	 *
	 * @return  bool    True if the two strings are exactly the same.
	 */
	protected function timingSafeCompare($known, $unknown)
	{
		// Prevent issues if string length is 0
		$known .= chr(0);
		$unknown .= chr(0);

		$knownLength = strlen($known);
		$unknownLength = strlen($unknown);

		// Set the result to the difference between the lengths
		$result = $knownLength - $unknownLength;

		// Note that we ALWAYS iterate over the user-supplied length to prevent leaking length info.
		for ($i = 0; $i < $unknownLength; $i++) {
			// Using % here is a trick to prevent notices. It's safe, since
			// if the lengths are different, $result is already non-0
			$result |= (ord($known[$i % $knownLength]) ^ ord($unknown[$i]));
		}

		// They are only identical strings if $result is exactly 0...
		return $result === 0;
	}
}
