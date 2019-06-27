<?php

namespace Drupal\social_auth_dropbox\Plugin\Network;

use Drupal\Core\Url;
use Drupal\social_api\SocialApiException;
use Drupal\social_auth\Plugin\Network\NetworkBase;
use Drupal\social_auth_dropbox\Settings\DropboxAuthSettings;
use Stevenmaguire\OAuth2\Client\Provider\Dropbox;

/**
 * Defines a Network Plugin for Social Auth Dropbox.
 *
 * @package Drupal\social_auth_dropbox\Plugin\Network
 *
 * @Network(
 *   id = "social_auth_dropbox",
 *   social_network = "Dropbox",
 *   type = "social_auth",
 *   handlers = {
 *     "settings": {
 *       "class": "\Drupal\social_auth_dropbox\Settings\DropboxAuthSettings",
 *       "config_id": "social_auth_dropbox.settings"
 *     }
 *   }
 * )
 */
class DropboxAuth extends NetworkBase implements DropboxAuthInterface {

  /**
   * Sets the underlying SDK library.
   *
   * @return \Stevenmaguire\OAuth2\Client\Provider\Dropbox|false
   *   The initialized 3rd party library instance.
   *
   * @throws \Drupal\social_api\SocialApiException
   *   If the SDK library does not exist.
   */
  protected function initSdk() {

    $class_name = 'Stevenmaguire\OAuth2\Client\Provider\Dropbox';
    if (!class_exists($class_name)) {
      throw new SocialApiException(sprintf('The Dropbox library for PHP League OAuth2 not found. Class: %s.', $class_name));
    }

    /* @var \Drupal\social_auth_dropbox\Settings\DropboxAuthSettings $settings */
    $settings = $this->settings;

    if ($this->validateConfig($settings)) {
      // All these settings are mandatory.
      $league_settings = [
        'clientId' => $settings->getAppKey(),
        'clientSecret' => $settings->getAppSecret(),
        'redirectUri' => Url::fromRoute('social_auth_dropbox.callback')->setAbsolute()->toString(),
      ];

      // Proxy configuration data for outward proxy.
      $proxyUrl = $this->siteSettings->get('http_client_config')['proxy']['http'];
      if ($proxyUrl) {
        $league_settings['proxy'] = $proxyUrl;
      }

      return new Dropbox($league_settings);
    }

    return FALSE;
  }

  /**
   * Checks that module is configured.
   *
   * @param \Drupal\social_auth_dropbox\Settings\DropboxAuthSettings $settings
   *   The Dropbox auth settings.
   *
   * @return bool
   *   True if module is configured.
   *   False otherwise.
   */
  protected function validateConfig(DropboxAuthSettings $settings) {
    $app_key = $settings->getAppKey();
    $app_secret = $settings->getAppSecret();
    if (!$app_key || !$app_secret) {
      $this->loggerFactory
        ->get('social_auth_dropbox')
        ->error('Define App Key and App Secret on module settings.');

      return FALSE;
    }

    return TRUE;
  }

}
