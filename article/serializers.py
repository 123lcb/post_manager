from rest_framework import serializers
from article.models import Article

class ArticleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Article
        fields = ['id', 'title', 'content', 'created_at', 'updated_at']
        read_only_fields = ['id', 'author', 'created_at', 'updated_at']

    def create(self, validated_data):
        # 自动关联当前登录用户
        validated_data['author'] = self.context['request'].user
        return super().create(validated_data)