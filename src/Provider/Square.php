<?php

namespace Wheniwork\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Square extends AbstractProvider
{
    use BearerAuthorizationTrait;
    public $debug = false;

    public $scopeSeparator = ' ';
    public $defaultScopes = [];
    public $accessTokenResourceOwnerId = null;
    private $responseError = 'error';

    /**
     * Get a Square connect URL, depending on path.
     *
     * @param  string $path
     * @return string
     */
    public function getConnectUrl($path)
    {
        $sandbox = $this->debug ? 'sandbox' : '';
        return "https://connect.squareup{$sandbox}.com/{$path}";
    }

    public function getBaseAuthorizationUrl()
    {
        return $this->getConnectUrl('oauth2/authorize');
    }

    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->getConnectUrl('oauth2/token');
    }

    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->getConnectUrl('v1/me');
    }

    public function getDefaultScopes()
    {
        return $this->defaultScopes;
    }

    public function getAccessTokenResourceOwnerId()
    {
      return $this->accessTokenResourceOwnerId ?: parent::getAccessTokenResourceOwnerId();
    }

    public function getScopeSeparator()
    {
        return $this->scopeSeparator;
    }

    public function userDetails($response, AccessToken $token)
    {
        // Ensure the response is converted to an array, recursively
        $response = json_decode(json_encode($response), true);
        $user = new SquareMerchant($response);
        return $user;
    }

    protected function fetchUserDetails(AccessToken $token)
    {
        $this->headers['Authorization'] = 'Bearer ' . $token->accessToken;
        $this->headers['Accept']        = 'application/json';

        return parent::fetchUserDetails($token);
    }

    protected function prepareAccessTokenResult(array $result)
    {
        // Square uses a ISO 8601 timestamp to represent the expiration date.
        // https://docs.connect.squareup.com/api/oauth/#post-token
        if (array_key_exists('expires_in', $result)) {
          $result['expires_in'] = strtotime($result['expires_at']) - time();
        }

        return $result;
    }

    /**
     * @inheritdoc
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        // TODO: Re-evaluate what this did and get it working with the new version
        // if (!empty($data[$this->responseError])) {
        //     $error = $data[$this->responseError];
        //     $code  = $this->responseCode ? $data[$this->responseCode] : 0;
        //     throw new IdentityProviderException($error, $code, $data);
        // }
    }
    /**
     * @inheritdoc
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new GenericResourceOwner($response, $this->responseResourceOwnerId);
    }
}