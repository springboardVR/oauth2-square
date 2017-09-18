<?php

namespace Wheniwork\OAuth2\Client\Grant;

use League\OAuth2\Client\Token\AccessToken as AccessToken;
use League\OAuth2\Client\Grant\AbstractGrant;

class RenewToken extends AbstractGrant
{
    /**
     * @var  string
     */
    protected $accessToken;

    /**
     * @param  AccessToken $token
     */
    public function __construct(AccessToken $token = null)
    {
        if ($token) {
            $this->accessToken = $token->getToken();
        }
    }

    public function __toString()
    {
        return 'renew_token';
    }

    public function prepRequestParams($defaultParams, $params)
    {
        if (empty($params['access_token'])) {
            if (!$this->accessToken) {
                throw new \BadMethodCallException('Missing access_token');
            }
            $params['access_token'] = $this->accessToken;
        }

        return array_merge($defaultParams, $params);
    }

    public function handleResponse($response = [])
    {
        return new AccessToken($response);
    }

    /**
     * @inheritdoc
     */
    protected function getName()
    {
        return 'renew_token';
    }
    /**
     * @inheritdoc
     */
    protected function getRequiredRequestParameters()
    {
        return [
            'renew_token',
        ];
    }
}
