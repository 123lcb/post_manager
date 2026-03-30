from django.core.management.base import BaseCommand
from django.utils import timezone
from article.models import Article
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Permanently delete articles that have been in trash for over 30 days'

    def handle(self, *args, **options):
        # 计算30天前的日期
        cutoff_date = timezone.now() - timezone.timedelta(days=30)

        # 获取符合条件的文章
        articles = Article.objects.filter(
            is_deleted=True,
            deleted_at__lte=cutoff_date
        )

        count = articles.count()

        if count > 0:
            # 执行删除
            articles.delete()
            msg = f"已永久删除 {count} 篇回收站中的旧文章"
            self.stdout.write(self.style.SUCCESS(msg))
            logger.info(msg)
        else:
            self.stdout.write("没有需要清理的回收站文章")