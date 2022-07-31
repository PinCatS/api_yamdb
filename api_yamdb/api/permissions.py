from rest_framework import permissions

from users.models import ROLES


class IsReadOnly(permissions.BasePermission):
    '''
    Global permission to only allow admin users to edit it.
    '''

    def has_permission(self, request, view):
        # Read permissions are allowed to any request but other
        # only to the admin user
        return request.method in permissions.SAFE_METHODS


class IsAdmin(permissions.BasePermission):
    '''
    Global permission to only allow admin users to edit it.
    '''

    def has_permission(self, request, view):
        # Read permissions are allowed to any request but other
        # only to the admin user
        if request.user.is_anonymous:
            return False
        return request.user.role == ROLES.admin.name

    def has_object_permission(self, request, view, obj):
        if request.user.is_anonymous:
            return False
        return request.user.role == ROLES.admin.name


class IsSuperuser(permissions.BasePermission):
    '''
    Global permission to only allow admin users to edit it.
    '''

    def has_permission(self, request, view):
        # Read permissions are allowed to any request but other
        # only to the admin user
        return request.user.is_superuser

    def has_object_permission(self, request, view, obj):
        return request.user.is_superuser


class IsModerator(permissions.BasePermission):
    '''
    Global permission to only allow admin users to edit it.
    '''

    def has_permission(self, request, view):
        # Read permissions are allowed to any request but other
        # only to the admin user
        if request.user.is_anonymous:
            return False
        return request.user.role == ROLES.moderator.name

    def has_object_permission(self, request, view, obj):
        if request.user.is_anonymous:
            return False
        return request.user.role == ROLES.moderator.name


class IsAuthor(permissions.BasePermission):
    '''
    Check permissions for read-only and write request.
    '''

    def has_object_permission(self, request, view, obj):
        return obj.author == request.user
