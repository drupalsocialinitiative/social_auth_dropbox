<?php

namespace Drupal\social_auth_dropbox\Controller;

use Drupal\Core\Messenger\MessengerInterface;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\Controller\OAuth2ControllerBase;
use Drupal\social_auth\SocialAuthDataHandler;
use Drupal\social_auth\User\UserAuthenticator;
use Drupal\social_auth_dropbox\DropboxAuthManager;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Returns responses for Social Auth Dropbox routes.
 */
class DropboxAuthController extends OAuth2ControllerBase {

  use ArrayAccessorTrait;

  /**
   * DropboxAuthController constructor.
   *
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of social_auth_dropbox network plugin.
   * @param \Drupal\social_auth\User\UserAuthenticator $user_authenticator
   *   Manages user login/registration.
   * @param \Drupal\social_auth_dropbox\DropboxAuthManager $dropbox_manager
   *   Used to manage authentication methods.
   * @param \Symfony\Component\HttpFoundation\RequestStack $request
   *   Used to access GET parameters.
   * @param \Drupal\social_auth\SocialAuthDataHandler $data_handler
   *   SocialAuthDataHandler object.
   */
  public function __construct(MessengerInterface $messenger,
                              NetworkManager $network_manager,
                              UserAuthenticator $user_authenticator,
                              DropboxAuthManager $dropbox_manager,
                              RequestStack $request,
                              SocialAuthDataHandler $data_handler) {

    parent::__construct('Social Auth Dropbox', 'social_auth_dropbox', $messenger, $network_manager, $user_authenticator, $dropbox_manager, $request, $data_handler);
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('messenger'),
      $container->get('plugin.network.manager'),
      $container->get('social_auth.user_authenticator'),
      $container->get('social_auth_dropbox.manager'),
      $container->get('request_stack'),
      $container->get('social_auth.data_handler')
    );
  }

  /**
   * Response for path 'user/login/dropbox/callback'.
   *
   * Dropbox returns the user here after user has authenticated.
   */
  public function callback() {

    // Checks if authentication failed.
    if ($this->request->getCurrentRequest()->query->has('error')) {
      $this->messenger->addError('You could not be authenticated.');

      return $this->redirect('user.login');
    }

    /* @var \Stevenmaguire\OAuth2\Client\Provider\DropboxResourceOwner|null $profile */
    $profile = $this->processCallback();

    // If authentication was successful.
    if ($profile !== NULL) {

      // Gets (or not) extra initial data.
      $data = $this->userAuthenticator->checkProviderIsAssociated($profile->getId()) ? FALSE : $this->providerManager->getExtraDetails();

      $response = $profile->toArray();
      $email = $this->getValueByKey($response, 'email');
      $picture = $this->getValueByKey($response, 'profile_photo_url');

      return $this->userAuthenticator->authenticateUser($profile->getName(), $email, $profile->getId(), $this->providerManager->getAccessToken(), $picture, $data);
    }

    return $this->redirect('user.login');
  }

}
