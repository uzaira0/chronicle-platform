object DistributionSpecialAccess {
    fun notificationListenerAccessGranted() {
        manager.isNotificationListenerAccessGranted(component)
        NotificationManagerCompat.getEnabledListenerPackages(context)
    }
}
