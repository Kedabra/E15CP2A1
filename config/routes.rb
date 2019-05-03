Rails.application.routes.draw do
  devise_for :users, controllers: {
      registration: 'users/registration'
  }

  resources :histories


  root "histories#index"
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
end
