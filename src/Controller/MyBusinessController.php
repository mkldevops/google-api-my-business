<?php

namespace App\Controller;

use Google\Client;
use Google\Service\Exception;
use Google\Service\MyBusinessBusinessInformation;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

class MyBusinessController extends AbstractController
{
    /**
     * @throws Exception
     */
    #[Route('/my-business', name: 'app_my_business')]
    public function index(Request $request): Response
    {
        $client = new Client();
        /** @var AccessToken $accessToken */
        $accessToken = $request
            ->getSession()
            ->get('access_token');

        $client->setAccessToken($accessToken->getToken());

        $myBusiness = new MyBusinessBusinessInformation($client);

        return $this->render('my_business/index.html.twig', [
            'myBusiness' => $myBusiness,
        ]);
    }
}
