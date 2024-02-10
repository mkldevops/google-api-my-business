<?php

namespace App\Controller;

use App\Security\Enum\ServiceAuthEnum;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_USER')]
class HomeController extends AbstractController
{
    /**
     * @throws IdentityProviderException
     */
    #[Route('/', name: 'app_home')]
    public function __invoke(ClientRegistry $clientRegistry): Response
    {
        $client = $clientRegistry->getClient(ServiceAuthEnum::GOOGLE->value);
        $client->setAsStateless();
        dump($client);

        return $this->render('home/index.html.twig');
    }
}
