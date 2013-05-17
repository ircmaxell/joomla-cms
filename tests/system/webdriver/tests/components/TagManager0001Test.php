<?php
/**
 * @package     Joomla.Test
 * @subpackage  Webdriver
 *
 * @copyright   Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE
 */
require_once 'JoomlaWebdriverTestCase.php';

use SeleniumClient\WebDriver;

/**
 * This class tests the  Tags: Add / Edit  Screen.
 *
 * @package     Joomla.Test
 * @subpackage  Webdriver
 * @since       3.0
 */
class TagManager0001Test extends JoomlaWebdriverTestCase
{
  	/**
	 * The page class being tested.
	 *
	 * @var     TagManagerPage
	 * @since   3.0
	 */
  	protected $tagManagerPage = null;

	/**
	 * Login to back end and navigate to menu Tags.
	 *
	 * @since   3.0
	 */
	public function setUp()
	{
		parent::setUp();
		$cpPage = $this->doAdminLogin();
		$this->tagManagerPage = $cpPage->clickMenu('Tags', 'TagManagerPage');
	}

	/**
	 * Logout and close test.
	 *
	 * @since   3.0
	 */
	public function tearDown()
	{
		$this->doAdminLogout();
		parent::tearDown();
	}

	/**
	 * @test
	 */
	public function constructor_OpenEditScreen_TagEditOpened()
	{
		$this->tagManagerPage->clickButton('new');
		$tagEditPage = $this->getPageObject('TagEditPage');
		$tagEditPage->clickButton('cancel');
		$this->tagManagerPage = $this->getPageObject('TagManagerPage');
	}

	/**
	 * @test
	 */
	public function addTag_WithGivenFields_TagAdded()
	{
		$salt = rand();
		$tagName = 'Tag' . $salt;
		$this->assertFalse($this->tagManagerPage->getRowNumber($tagName), 'Test Tag should not be present');
		$this->tagManagerPage->addTag($tagName);
		$message = $this->tagManagerPage->getAlertMessage();
		$this->assertTrue(strpos($message, 'Tag successfully saved') >= 0, 'Tag save should return success');
		$this->assertEquals(1, $this->tagManagerPage->getRowNumber($tagName), 'Test Tag should be in row 2');
		$this->tagManagerPage->deleteItem($tagName);
		$this->assertFalse($this->tagManagerPage->getRowNumber($tagName), 'Test Tag should not be present');
	}

}
