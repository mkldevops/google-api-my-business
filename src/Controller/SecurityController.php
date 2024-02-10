<?php

namespace App\Controller;

use App\Security\Enum\ServiceAuthEnum;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class SecurityController extends AbstractController
{
    private const array SCOPES = [
        ServiceAuthEnum::GOOGLE->value => ['https://www.googleapis.com/auth/business.manage'],
    ];

    #[Route('/login', name: 'app_login')]
    public function login(): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('app_home');
        }

        return $this->render('security/login.html.twig');
    }

    /**
     * @throws \Exception
     */
    #[Route('/logout', name: 'app_logout')]
    public function logout(): void
    {
        throw new \Exception('This method can be blank - it will be intercepted by the logout key on your firewall');
    }

    #[Route('/oauth/connect/{service}', name: 'app_oauth_connect', methods: ['GET'])]
    public function home(ServiceAuthEnum $service, ClientRegistry $clientRegistry): RedirectResponse
    {
        return $clientRegistry
            ->getClient($service->value)
            ->redirect(self::SCOPES[$service->value]);
    }

    #[Route('/oauth/check/{service}', name: 'app_oauth_check', methods: ['GET', 'POST'])]
    public function check(ServiceAuthEnum $service): Response
    {

        return new Response(status: Response::HTTP_OK);
    }
}
