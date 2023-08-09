from django.urls import path
from .import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.index, name='index'),
    path('index/', views.index, name='index'),
    path('encode/', views.encode, name="encode"),
    path('decode/', views.decode, name="decode"),
    path('encode_result/', views.encode_result, name="encode_result"),
    path('decode_result/', views.decode_result, name="decode_result"),
]

if settings.DEBUG:
    urlpatterns+=static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)