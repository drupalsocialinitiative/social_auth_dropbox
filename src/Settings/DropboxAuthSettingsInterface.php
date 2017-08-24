<?php

namespace Drupal\social_auth_dropbox\Settings;

/**
 * Defines an interface for Social Auth Dropbox settings.
 */
interface DropboxAuthSettingsInterface {

  /**
   * Gets the app ley.
   *
   * @return string
   *   The app ley.
   */
  public function getAppKey();

  /**
   * Gets the app secret.
   *
   * @return string
   *   The app secret.
   */
  public function getAppSecret();

}
