from django.db import models
from django.utils import timezone


class ScanHistory(models.Model):
    """
    Modèle pour stocker l'historique des scans effectués
    """
    STATUS_CHOICES = [
        ('pending', 'En attente'),
        ('running', 'En cours'),
        ('completed', 'Terminé'),
        ('failed', 'Échoué'),
    ]
    
    MODE_CHOICES = [
        ('Rapide', 'Rapide'),
        ('Complet', 'Complet'),
        ('Personnalisé', 'Personnalisé'),
    ]
    
    target = models.CharField(max_length=255, verbose_name="Cible (IP/Hôte)")
    ports = models.CharField(max_length=100, blank=True, null=True, verbose_name="Ports")
    mode = models.CharField(max_length=20, choices=MODE_CHOICES, verbose_name="Mode de scan")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending', verbose_name="Statut")
    results = models.JSONField(blank=True, null=True, verbose_name="Résultats")
    error_message = models.TextField(blank=True, null=True, verbose_name="Message d'erreur")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Créé le")
    completed_at = models.DateTimeField(blank=True, null=True, verbose_name="Terminé le")
    
    class Meta:
        verbose_name = "Historique de scan"
        verbose_name_plural = "Historiques de scans"
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.target} - {self.mode} ({self.status})"
