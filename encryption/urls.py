from django.urls import path

from . import views

urlpatterns = [
    path('secure-api/', views.SecureAPIView, name='secure-api'),
]
