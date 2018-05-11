<?php

namespace Drupal\social_auth_dropbox\Controller;

use Drupal\Core\Controller\ControllerBase;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\SocialAuthUserManager;
use Drupal\social_auth_dropbox\DropboxAuthManager;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Returns responses for Simple Dropbox Connect module routes.
 */
class DropboxAuthController extends ControllerBase {

  use ArrayAccessorTrait;

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_api\Plugin\NetworkManager
   */
  private $networkManager;

  /**
   * The user manager.
   *
   * @var \Drupal\social_auth\SocialAuthUserManager
   */
  private $userManager;

  /**
   * The dropbox authentication manager.
   *
   * @var \Drupal\social_auth_dropbox\DropboxAuthManager
   */
  private $dropboxManager;

  /**
   * Used to access GET parameters.
   *
   * @var \Symfony\Component\HttpFoundation\RequestStack
   */
  private $request;

  /**
   * The Social Auth Data Handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $dataHandler;

  /**
   * DropboxAuthController constructor.
   *
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_dropbox network plugin.
   * @param \Drupal\social_auth\SocialAuthUserManager $user_manager
   *   Manages user login/registration.
   * @param \Drupal\social_auth_dropbox\DropboxAuthManager $dropbox_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $social_auth_data_handler
   *   SocialAuthDataHandler object.
   */
  public function __construct(NetworkManager $network_manager,
                              SocialAuthUserManager $user_manager,
                              DropboxAuthManager $dropbox_manager,
                              RequestStack $request,
                              SocialAuthDataHandler $social_auth_data_handler) {

    $this->networkManager = $network_manager;
    $this->userManager = $user_manager;
    $this->dropboxManager = $dropbox_manager;
    $this->request = $request;
    $this->dataHandler = $social_auth_data_handler;

    // Sets the plugin id.
    $this->userManager->setPluginId('social_auth_dropbox');

    // Sets the session keys to nullify if user could not logged in.
    $this->userManager->setSessionKeysToNullify(['access_token', 'oauth2state']);
    $this->setting = $this->config('social_auth_dropbox.settings');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_manager'),
      $container->get('social_auth_dropbox.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.data_handler'),
      $container->get('logger.factory')
    );
  }

  /**
   * Response for path 'user/login/dropbox'.
   *
   * Redirects the user to Dropbox for authentication.
   */
  public function redirectToDropbox() {
    /* @var \Stevenmaguire\OAuth2\Client\Provider\Dropbox|false $dropbox */
    $dropbox = $this->networkManager->createInstance('social_auth_dropbox')->getSdk();

    // If dropbox client could not be obtained.
    if (!$dropbox) {
      drupal_set_message($this->t('Social Auth Dropbox not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Dropbox service was returned, inject it to $dropboxManager.
    $this->dropboxManager->setClient($dropbox);

    // Generates the URL where the user will be redirected for authentication.
    $dropbox_login_url = $this->dropboxManager->getAuthorizationUrl();

    $state = $this->dropboxManager->getState();

    $this->dataHandler->set('oauth2state', $state);

    return new TrustedRedirectResponse($dropbox_login_url);
  }

  /**
   * Response for path 'user/login/dropbox/callback'.
   *
   * Dropbox returns the user here after user has authenticated in Dropbox.
   */
  public function callback() {
    // Checks if user cancel login via Dropbox.
    $error = $this->request->getCurrentRequest()->get('error');
    if ($error == 'access_denied') {
      drupal_set_message($this->t('You could not be authenticated.'), 'error');
      return $this->redirect('user.login');
    }

    /* @var \Stevenmaguire\OAuth2\Client\Provider\Dropbox|false $dropbox */
    $dropbox = $this->networkManager->createInstance('social_auth_dropbox')->getSdk();

    // If Dropbox client could not be obtained.
    if (!$dropbox) {
      drupal_set_message($this->t('Social Auth Dropbox not configured properly. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    $state = $this->dataHandler->get('oauth2state');

    // Retreives $_GET['state'].
    $retrievedState = $this->request->getCurrentRequest()->query->get('state');
    if (empty($retrievedState) || ($retrievedState !== $state)) {
      $this->userManager->nullifySessionKeys();
      drupal_set_message($this->t('Dropbox login failed. Unvalid OAuth2 State.'), 'error');
      return $this->redirect('user.login');
    }

    $this->dropboxManager->setClient($dropbox)->authenticate();

    // Saves access token to session.
    $this->dataHandler->set('access_token', $this->dropboxManager->getAccessToken());

    // Gets user's info from Dropbox API.
    /* @var \Stevenmaguire\OAuth2\Client\Provider\DropboxResourceOwner $profile */
    if (!$profile = $this->dropboxManager->getUserInfo()) {
      drupal_set_message($this->t('Dropbox login failed, could not load Dropbox profile. Contact site administrator.'), 'error');
      return $this->redirect('user.login');
    }

    // Gets (or not) extra initial data.
    $data = $this->userManager->checkIfUserExists($profile->getId()) ? NULL : $this->dropboxManager->getExtraDetails();

    $response = $profile->toArray();
    $email = $this->getValueByKey($response, 'email');
    $picture = $this->getValueByKey($response, 'profile_photo_url');

    // If user information could be retrieved.
    return $this->userManager->authenticateUser($profile->getName(), $email, $profile->getId(), $this->dropboxManager->getAccessToken(), $picture, $data);
  }

}
