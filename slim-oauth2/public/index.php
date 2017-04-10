<?php
session_start();

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

require dirname(__DIR__) . "/vendor/autoload.php";

$app = new \Slim\App;

/**
 * @param $request
 * @param $response
 * @param $next
 * @return mixed
 */
$mw = function ($request, $response, $next) {
    if ($_SESSION['user']) {
        return $next($request, $response);
    }
    return $response->withStatus(403)->withHeader('Location', '/login');
};

/**
 * Example routes
 */
$app->get('/', function (Request $request, Response $response) {
    $user = $_SESSION['user'];
    $response->getBody()->write("Hello, " . $user['profile']['first_name']);

    return $response;
})->add($mw);

/**
 * Authenticate with OAuth2 workflow
 */
$app->get('/login', function (Request $request, Response $response) {
    $provider = new \Previewtechs\Oauth2\Client\Provider([
        'clientId' => '{CLIENT ID}',
        'clientSecret' => '{CLIENT SECRET}',
        'redirectUri' => '{WHITELISTED REDIRECT URI}'
    ]);

    $loginUrl = $provider->getAuthorizationUrl();

    if (isset($_GET['code'])) {

        //Request access token & refresh token
        $accessToken = $provider->getAccessToken('authorization_code', [
            'code' => $_GET['code']
        ]);

        $tokens = [
            'token' => $accessToken->getToken(),
            'refresh_token' => $accessToken->getRefreshToken(),
            'expired_on' => $accessToken->getExpires(),
            'is_expired' => $accessToken->hasExpired(),
        ];

        //Store the token to persistent storage. We are storing that in session
        $_SESSION['token'] = $tokens;

        //Now request user's basic information through our 'user-info' API
        $request = $provider->getAuthenticatedRequest(
            'GET',
            'https://user-info.previewtechsapis.com/v1/me',
            $tokens['token']
        );

        $client = new \GuzzleHttp\Client();
        $result = $client->send($request);
        $ApiResponse = json_decode($result->getBody()->getContents(), true);

        //If success, set the user in session, otherwise re-authenticate
        if ($ApiResponse['success'] === true) {
            $_SESSION['user'] = $ApiResponse['data'];
        } else {
            return $response->getBody()->write("Something went wrong! Please again <a href='{$loginUrl}'>Authenticate</a>");
        }

        //If everything goes well, redirect to homepage
        return $response->withRedirect('/');
    }

    $response->getBody()->write("<a href='{$loginUrl}'>Authenticate</a>");

    return $response;
});

//Destroy the session
$app->get('/logout', function (Request $request, Response $response) {
    session_destroy();
    return $response->withRedirect('/');
});

$app->run();