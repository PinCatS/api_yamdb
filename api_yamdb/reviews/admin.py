from django.contrib import admin

from .models import Category, Genre, Review, Title, Comment


class CategoryAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'slug',
    )
    search_fields = (
        'name',
        'slug',
    )


class GenreAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'slug',
    )
    search_fields = (
        'name',
        'slug',
    )


class TitleAdmin(admin.ModelAdmin):
    list_display = (
        'name',
        'year',
        'description',
        'category',
    )
    search_fields = (
        'name',
        'description',
    )
    list_filter = (
        'year',
        'genre',
        'category',
    )
    empty_value_display = '-пусто-'
    list_editable = ('category',)


class ReviewAdmin(admin.ModelAdmin):
    list_display = (
        'text',
        'author',
        'score',
        'pub_date',
        'title'
    )
    search_fields = (
        'author',
        'title',
    )


class CommentAdmin(admin.ModelAdmin):
    list_display = (
        'text',
        'author',
        'pub_date',
        'review'
    )
    search_fields = (
        'author',
        'review',
    )


admin.site.register(Category, CategoryAdmin)
admin.site.register(Genre, GenreAdmin)
admin.site.register(Title, TitleAdmin)
admin.site.register(Review, ReviewAdmin)
admin.site.register(Comment, CommentAdmin)
