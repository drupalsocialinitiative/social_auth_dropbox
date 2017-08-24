<?php

namespace Drupal\social_auth_dropbox\Plugin\Network;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Logger\LoggerChannelFactoryInterface;
use Drupal\Core\Routing\RequestContext;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_api\Plugin\NetworkBase;
use Drupal\social_api\SocialApiException;
use Drupal\social_auth_dropbox\Settings\DropboxAuthSettings;
use Symfony\Component\DependencyInjection\ContainerInterface;
use League\OAuth2\Client\Provider\Dropbox;
use Drupal\Core\Site\Settings;

/**
 * Defines a Network Plugin for Social Auth Dropbox.
 *
 * @package Drupal\simple_dropbox_connect\Plugin\Network
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
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  protected $dataHandler;

  /**
   * The logger factory.
   *
   * @var \Drupal\Core\Logger\LoggerChannelFactory
   */
  protected $loggerFactory;

  /**
   * The request context object.
   *
   * @var \Drupal\Core\Routing\RequestContext
   */
  protected $requestContext;

  /**
   * The site settings.
   *
   * @var \Drupal\Core\Site\Settings
   */
  protected $siteSettings;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    return new static(
      $container->get('social_auth.social_auth_data_handler'),
      $configuration,
      $plugin_id,
      $plugin_definition,
      $container->get('entity_type.manager'),
      $container->get('config.factory'),
      $container->get('logger.factory'),
      $container->get('router.request_context'),
      $container->get('settings')
    );
  }

  /**
   * DropboxAuth constructor.
   *
   * @param \Drupal\social_auth\SocialAuthDataHandler $data_handler
   *   The data handler.
   * @param array $configuration
   *   A configuration array containing information about the plugin instance.
   * @param string $plugin_id
   *   The plugin_id for the plugin instance.
   * @param array $plugin_definition
   *   The plugin implementation definition.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity type manager.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The configuration factory object.
   * @param \Drupal\Core\Logger\LoggerChannelFactoryInterface $logger_factory
   *   The logger factory.
   * @param \Drupal\Core\Routing\RequestContext $requestContext
   *   The Request Context Object.
   * @param \Drupal\Core\Site\Settings $settings
   *   The settings factory.
   */
  public function __construct(SocialAuthDataHandler $data_handler,
                              array $configuration,
                              $plugin_id,
                              array $plugin_definition,
                              EntityTypeManagerInterface $entity_type_manager,
                              ConfigFactoryInterface $config_factory,
                              LoggerChannelFactoryInterface $logger_factory,
                              RequestContext $requestContext,
                              Settings $settings
  ) {

    parent::__construct($configuration, $plugin_id, $plugin_definition, $entity_type_manager, $config_factory);

    $this->dataHandler = $data_handler;
    $this->loggerFactory = $logger_factory;
    $this->requestContext = $requestContext;
    $this->siteSettings = $settings;
  }

  /**
   * Sets the underlying SDK library.
   *
   * @return \League\OAuth2\Client\Provider\Dropbox
   *   The initialized 3rd party library instance.
   *
   * @throws SocialApiException
   *   If the SDK library does not exist.
   */
  protected function initSdk() {

    $class_name = 'Stevenmaguire\OAuth2\Client\Provider\Dropbox';
    if (!class_exists($class_name)) {
      throw new SocialApiException(sprintf('The Dropbox Library for the league oAuth not found. Class: %s.', $class_name));
    }
    /* @var \Drupal\social_auth_dropbox\Settings\DropboxAuthSettings $settings */
    $settings = $this->settings;
    // Proxy configuration data for outward proxy.
    $proxyUrl = $this->siteSettings->get("http_client_config")["proxy"]["http"];
    if ($this->validateConfig($settings)) {
      // All these settings are mandatory.
      if ($proxyUrl) {
        $league_settings = [
          'clientId' => $settings->getAppKey(),
          'clientSecret' => $settings->getAppSecret(),
          'redirectUri' => $this->requestContext->getCompleteBaseUrl() . '/user/login/dropbox/callback',
          'proxy' => $proxyUrl,
        ];
      }
      else {
        $league_settings = [
          'clientId' => $settings->getAppKey(),
          'clientSecret' => $settings->getAppSecret(),
          'redirectUri' => $this->requestContext->getCompleteBaseUrl() . '/user/login/dropbox/callback',
        ];
      }

      return new \Stevenmaguire\OAuth2\Client\Provider\Dropbox($league_settings);
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
