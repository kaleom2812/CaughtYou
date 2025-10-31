# tracker/urls.py
from django.urls import path
from .views import tx_search, last10_from_tx , download_tx_pdf_plain , about
from tracker import views
urlpatterns = [
    path("", about , name="Aboutme"),
    path("search/", tx_search, name="tx_search"),
    path("last10/", last10_from_tx, name="last10_from_tx"),   # <-- new page
    path("search/last10/",last10_from_tx, name="last10_from_tx"),
    path("download_tx_pdf_plain/",download_tx_pdf_plain, name="download_tx_pdf_plain"),
    path("last10/", last10_from_tx, name="last10_from_tx"),
    path('download_pdf/', download_tx_pdf_plain, name='download_tx_pdf_plain'),
    path('', views.tx_search, name='tx_search'),               # your existing
    path('search/', views.tx_search, name='tx_search_search'),
    path('last10/', views.last10_from_tx, name='last10_from_tx'),
    path('last10/print', views.last10_print_pdf, name='last10_print_pdf'),
    path("", views.about, name="home"),  # Landing page
    path("about/", views.about, name="about"),
]
    