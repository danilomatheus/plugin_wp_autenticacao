<?php

/*
Plugin Name: Wp JWT Authentication
Description: Plugin que realiza o login via JWT e permite utilizar requisições autenticadas sem cookie.
Version: 1.0
Author: Danilo Matheus
Author URI: https://www.linkedin.com/in/danilomthsouza/
*/

include("jwt.php");

//criar uma rota para fazer lohgin via JWT

function wd_api_init()
{
  $namespace  = "wdjwt/v1";

  register_rest_route($namespace, '/login', array(
    'methods' => 'POST',
    'callback' => 'wd_api_login',
  ));
  register_rest_route($namespace, '/token/validate', array(
    'methods' => 'GET',
    'callback' => 'wd_api_token_validate',
  ));

  add_filter('rest_pre_dispatch', 'wd_rest_pre_dispatch', 10, 3);
}

function wd_rest_pre_dispatch($url, $server, $req)
{
  $params = $req->get_params();

  if (!empty($params['jwt'])) {
    $jwt = new JWT();

    $info = $jwt->validate($params['jwt']);

    if ($info && !empty($info->id)) {
      //através do id efetuar o login no wordpress
      wp_set_current_user($info->id);
    }
  }

}

function wd_api_token_validate($req)
{
  $array = array('valid' => false);
  $params = $req->get_params();

  if (!empty($params['jwt'])) {
    $jwt = new JWT();

    $info = $jwt->validate($params['jwt']);

    if ($info && !empty($info->id)) {
      $array['valid'] = true;
    }
  }
  return $array;
}

function wd_api_login($req)
{
  $array = array('logged' => false);
  $params = $req->get_params();

  $result = wp_signon(array(
    'user_login' => $params['username'],
    'user_password' => $params['password'],
  ));
  if (isset($result->data)) {
    $jwt = new JWT();
    $token = $jwt->create(array('id' => $result->data->ID));
    $array['logged'] = true;
    $array['token'] = $token;
  }
  return $array;
}

add_action("rest_api_init", "wd_api_init");
