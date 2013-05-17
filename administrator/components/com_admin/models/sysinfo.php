<?php
/**
 * @package     Joomla.Administrator
 * @subpackage  com_admin
 *
 * @copyright   Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

/**
 * Model for the display of system information.
 *
 * @package     Joomla.Administrator
 * @subpackage  com_admin
 * @since       1.6
 */
class AdminModelSysInfo extends JModelLegacy
{
	/**
	 * @var array Some PHP settings
	 * @since  1.6
	 */
	protected $php_settings = null;

	/**
	 * @var array Config values
	 * @since  1.6
	 */
	protected $config = null;

	/**
	 * @var array Some system values
	 * @since  1.6
	 */
	protected $info = null;

	/**
	 * @var string PHP info
	 * @since  1.6
	 */
	protected $php_info = null;

	/**
	 * Information about writable state of directories
	 *
	 * @var array
	 * @since  1.6
	 */
	protected $directories = null;

	/**
	 * The current editor.
	 *
	 * @var string
	 * @since  1.6
	 */
	protected $editor = null;

	/**
	 * Method to get the ChangeLog
	 *
     * @return  array  some php settings
	 *
	 * @since  1.6
	 */
	public function &getPhpSettings()
	{
		if (is_null($this->php_settings))
		{
			$this->php_settings = array();
			$this->php_settings['safe_mode']			= ini_get('safe_mode') == '1';
			$this->php_settings['display_errors']		= ini_get('display_errors') == '1';
			$this->php_settings['short_open_tag']		= ini_get('short_open_tag') == '1';
			$this->php_settings['file_uploads']			= ini_get('file_uploads') == '1';
			$this->php_settings['magic_quotes_gpc']		= ini_get('magic_quotes_gpc') == '1';
			$this->php_settings['register_globals']		= ini_get('register_globals') == '1';
			$this->php_settings['output_buffering']		= (bool) ini_get('output_buffering');
			$this->php_settings['open_basedir']			= ini_get('open_basedir');
			$this->php_settings['session.save_path']	= ini_get('session.save_path');
			$this->php_settings['session.auto_start']	= ini_get('session.auto_start');
			$this->php_settings['disable_functions']	= ini_get('disable_functions');
			$this->php_settings['xml']					= extension_loaded('xml');
			$this->php_settings['zlib']					= extension_loaded('zlib');
			$this->php_settings['zip']					= function_exists('zip_open') && function_exists('zip_read');
			$this->php_settings['mbstring']				= extension_loaded('mbstring');
			$this->php_settings['iconv']				= function_exists('iconv');
		}

		return $this->php_settings;
	}

	/**
	 * Method to get the config
	 *
     * @return  array  config values
	 *
	 * @since  1.6
	 */
	public function &getConfig()
	{
		if (is_null($this->config))
		{
			$registry = new JRegistry(new JConfig);
			$this->config = $registry->toArray();
			$hidden = array('host', 'user', 'password', 'ftp_user', 'ftp_pass', 'smtpuser', 'smtppass');
			foreach ($hidden as $key)
			{
				$this->config[$key] = 'xxxxxx';
			}
		}

		return $this->config;
	}

	/**
	 * Method to get the system information
	 *
     * @return  array  system information values
	 *
	 * @since   1.6
	 */
	public function &getInfo()
	{
		if (is_null($this->info))
		{
			$this->info = array();
			$version = new JVersion;
			$platform = new JPlatform;
			$db = JFactory::getDbo();
			if (isset($_SERVER['SERVER_SOFTWARE']))
			{
				$sf = $_SERVER['SERVER_SOFTWARE'];
			}
			else
			{
				$sf = getenv('SERVER_SOFTWARE');
			}
			$this->info['php']			= php_uname();
			$this->info['dbversion']	= $db->getVersion();
			$this->info['dbcollation']	= $db->getCollation();
			$this->info['phpversion']	= phpversion();
			$this->info['server']		= $sf;
			$this->info['sapi_name']	= php_sapi_name();
			$this->info['version']		= $version->getLongVersion();
			$this->info['platform']		= $platform->getLongVersion();
			$this->info['useragent']	= $_SERVER['HTTP_USER_AGENT'];
		}
		return $this->info;
	}

	/**
	 * Method to get the PHP info
	 *
     * @return  string  PHP info
	 *
	 * @since  1.6
	 */
	public function &getPHPInfo()
	{
		if (is_null($this->php_info))
		{
			ob_start();
			date_default_timezone_set('UTC');
			phpinfo(INFO_GENERAL | INFO_CONFIGURATION | INFO_MODULES);
			$phpinfo = ob_get_contents();
			ob_end_clean();
			preg_match_all('#<body[^>]*>(.*)</body>#siU', $phpinfo, $output);
			$output = preg_replace('#<table[^>]*>#', '<table class="table table-striped adminlist">', $output[1][0]);
			$output = preg_replace('#(\w),(\w)#', '\1, \2', $output);
			$output = preg_replace('#<hr />#', '', $output);
			$output = str_replace('<div class="center">', '', $output);
			$output = preg_replace('#<tr class="h">(.*)<\/tr>#', '<thead><tr class="h">$1</tr></thead><tbody>', $output);
			$output = str_replace('</table>', '</tbody></table>', $output);
			$output = str_replace('</div>', '', $output);
			$this->php_info = $output;
		}

		return $this->php_info;
	}

	/**
	 * Method to get the directory states
	 *
     * @return  array  States of directories
	 *
	 * @since  1.6
	 */
	public function getDirectory()
	{
		if (is_null($this->directories))
		{
			$this->directories = array();

			$registry = JFactory::getConfig();
			$cparams = JComponentHelper::getParams('com_media');

			$this->_addDirectory('administrator/components', JPATH_ADMINISTRATOR . '/components');
			$this->_addDirectory('administrator/language', JPATH_ADMINISTRATOR . '/language');

			// List all admin languages
			$admin_langs = new DirectoryIterator(JPATH_ADMINISTRATOR . '/language');
			foreach ($admin_langs as $alang)
			{
				if (!$alang->isDir() || $alang->isDot())
				{
					continue;
				}

				$name = $alang->getFilename();

				$this->_addDirectory('administrator/language/' . $name, JPATH_ADMINISTRATOR . '/language/' . $name);
			}

			// List all manifests folders
			$manifests = new DirectoryIterator(JPATH_ADMINISTRATOR . '/manifests');
			foreach ($manifests as $manifest)
			{
				if (!$manifest->isDir() || $manifest->isDot())
				{
					continue;
				}

				$name = $manifest->getFilename();

				$this->_addDirectory('administrator/manifests/' . $name, JPATH_ADMINISTRATOR . '/manifests/' . $name);
			}

			$this->_addDirectory('administrator/modules', JPATH_ADMINISTRATOR . '/modules');
			$this->_addDirectory('administrator/templates', JPATH_THEMES);

			$this->_addDirectory('components', JPATH_SITE . '/components');

			$this->_addDirectory($cparams->get('image_path'), JPATH_SITE . '/' . $cparams->get('image_path'));

			// List all images folders
			$image_folders = new DirectoryIterator(JPATH_SITE . '/' . $cparams->get('image_path'));
			foreach ($image_folders as $folder)
			{
				if (!$folder->isDir() || $folder->isDot())
				{
					continue;
				}

				$name = $manifest->getFilename();

				$this->_addDirectory('images/' . $name, JPATH_SITE . '/' . $cparams->get('image_path') . '/' . $name);
			}

			$this->_addDirectory('language', JPATH_SITE . '/language');

			// List all site languages
			$site_langs = new DirectoryIterator(JPATH_SITE . '/language');
			foreach ($site_langs as $alang)
			{
				if (!$alang->isDir() || $alang->isDot())
				{
					continue;
				}

				$name = $alang->getFilename();

				$this->_addDirectory('language/' . $name, JPATH_SITE . '/language/' . $name);
			}

			$this->_addDirectory('libraries', JPATH_LIBRARIES);

			$this->_addDirectory('media', JPATH_SITE . '/media');
			$this->_addDirectory('modules', JPATH_SITE . '/modules');
			$this->_addDirectory('plugins', JPATH_PLUGINS);

			$plugin_groups = new DirectoryIterator(JPATH_SITE . '/language');
			foreach ($plugin_groups as $folder)
			{
				if (!$alang->isDir() || $alang->isDot())
				{
					continue;
				}

				$name = $alang->getFilename();

				$this->_addDirectory('plugins/' . $name, JPATH_PLUGINS . '/' . $name);
			}

			$this->_addDirectory('templates', JPATH_SITE . '/templates');
			$this->_addDirectory('configuration.php', JPATH_CONFIGURATION . '/configuration.php');
			$this->_addDirectory('cache', JPATH_SITE.'/cache', 'COM_ADMIN_CACHE_DIRECTORY');
			$this->_addDirectory('administrator/cache', JPATH_CACHE, 'COM_ADMIN_CACHE_DIRECTORY');

			$this->_addDirectory($registry->get('log_path', JPATH_ROOT . '/log'), $registry->get('log_path', JPATH_ROOT . '/log'), 'COM_ADMIN_LOG_DIRECTORY');
			$this->_addDirectory($registry->get('tmp_path', JPATH_ROOT . '/tmp'), $registry->get('tmp_path', JPATH_ROOT . '/tmp'), 'COM_ADMIN_TEMP_DIRECTORY');
		}
		return $this->directories;
	}

	/**
	 * Method to add a directory
	 *
     * @return  void
	 * @since  1.6
	 */
	private function _addDirectory($name, $path, $message = '')
	{
		$this->directories[$name] = array('writable' => is_writable($path), 'message' => $message);
	}

	/**
	 * Method to get the editor
	 *
     * @return  string  The default editor
	 *
	 * @note: has to be removed (it is present in the config...)
	 *
	 * @since  1.6
	 */
	public function &getEditor()
	{
		if (is_null($this->editor))
		{
			$config = JFactory::getConfig();
			$this->editor = $config->get('editor');
		}
		return $this->editor;
	}
}
