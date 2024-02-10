<?php

namespace App\Security;

use App\Entity\User;
use App\Security\Enum\ServiceAuthEnum;
use League\OAuth2\Client\Provider\GoogleUser;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use RuntimeException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

use function is_string;

class GoogleAuthenticator extends AbstractOAuthAuthenticator
{
    protected ServiceAuthEnum $serviceAuth = ServiceAuthEnum::GOOGLE;

    protected function getUserFromResourceOwner(ResourceOwnerInterface $resourceOwner): User
    {
        if (!$resourceOwner instanceof GoogleUser) {
            throw new RuntimeException('ResourceOwner is not an instance of GoogleUser');
        }

        if (true !== ($resourceOwner->toArray()['email_verified'] ?? null)) {
            throw new AuthenticationException('Email is not verified');
        }

        if (!is_string($googleId = $resourceOwner->getId())) {
            throw new RuntimeException('GoogleId is not a string');
        }

        $email = (string) $resourceOwner->getEmail();
        $user = $this->userRepository->findOneBy([
            'email' => $email,
            'googleId' => $googleId,
        ]);

        if (null === $user) {
            $user = new User();
            $user->setEmail($email);
            $user->setRoles(['ROLE_USER']);
            $user->setGoogleId($googleId);
            $this->userRepository->add($user, true);
        }

        return $user;
    }
}
