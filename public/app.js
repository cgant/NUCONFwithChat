var App = angular.module('MyApp', ['ngCookies', 'ngResource', 'ngMessages', 'ngRoute', 'mgcrea.ngStrap']);
  
App.config(['$routeProvider',
  function($routeProvider) {
    $routeProvider.
      
    when('/login', {
        templateUrl: 'views/login.html',
        controller: 'LoginCtrl'
    }).
	  when('/registration', {
        templateUrl: 'views/registration.html',
        controller: 'registerCtrl'
	  }).
    when('/chat', {
        templateUrl: 'views/chat.html',
        controller: 'chatCtrl'
	  }).
      otherwise({
        redirectTo: '/'
      });
  }])
