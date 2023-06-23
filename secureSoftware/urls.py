from django.urls import path
from . import views

urlpatterns = [
    path('', views.home),
    path('process/sign/',views.sign_software),
    path('process/verify/',views.verify_software),
    path('process/',views.process_file)

]