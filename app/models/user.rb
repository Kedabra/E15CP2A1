class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  attr_accessor :email, :password, :password_confirmation, :remember_me, :name, :username
  has_many :histories
  validates :name, presence: true
  validates :username, presence: true, uniqueness: true
end
