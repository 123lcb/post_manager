# Post Manager（文章管理器）

这是一个基于 Django 的“文章管理 + 共享/审核 + 账号体系”的 Web 项目，支持富文本编辑、分级分类、软删除回收站、共享内容管理、收藏与用户资料维护，并提供基于 DeepSeek 的文本摘要/统计分析接口。

## 功能概览

### 1) 账号体系（`accounts/`）
- 注册、登录、退出
- 图片验证码（用于登录/注册）
- 邮箱验证码（用于注册与邮箱相关流程）
- 密码重置（通过邮箱验证码完成）
- 用户资料维护：昵称、性别、生日、地区/国家、简介、头像
- 管理员能力：
  - 冻结/解冻账号（`is_frozen`）
  - 查看管理员操作日志（`UserActionLog`）
- 收藏功能：收藏共享文章（`Favorite`）

### 2) 文章管理（`article/`）
- 文章增删改查
  - 富文本编辑（TinyMCE）
  - 文章可选图片上传
- 分类管理
  - 多级分类（MPTT 树结构），表单限制最多三级
  - 分类包含作者维度（不同作者互相隔离）
- 删除策略
  - 软删除到回收站（保留删除原因与删除时间）
  - 回收站支持恢复、永久删除、清空回收站（可按天数筛选）
- 文章分享
  - 将文章复制到 `ShareArticle`（共享文章池）
  - 共享文章详情支持评论

### 3) 内容审核与展示（`accounts/` + `article/`）
- 超级用户可对共享内容进行下架/恢复（`is_removed`）
- 前台展示共享文章列表，并支持搜索（标题/内容/作者/日期区间等）
- 共享文章下架/恢复由管理员页面发起

### 4) AI 摘要/统计分析（DeepSeek）
- 为文章内容生成摘要：`/article/<pk>/summary/`
- 为文章内容生成统计汇总：`/article/<pk>/statistical-summary/`
- 服务端会对结果做缓存，减少重复调用
- 调用依赖 `settings.py` 中的 `DEEPSEEK_API_KEY / DEEPSEEK_API_URL / DEEPSEEK_API_TIMEOUT / DEEPSEEK_CACHE_TIMEOUT`

## 技术栈
- Django 5.1
- MySQL（`django.db.backends.mysql`）
- Django REST Framework（依赖中出现，但当前主要逻辑偏模板视图）
- TinyMCE（富文本）
- django-simple-captcha（图片验证码）
- MySQL 相关驱动：`mysqlclient` / `mysql-connector-python`
- DeepSeek（摘要/统计调用）

## 目录结构（快速理解）
- `post_manager/`：项目级配置（`settings.py`、路由 `urls.py`）
- `accounts/`：账号、用户资料、冻结/日志、收藏、内容审核等
- `article/`：文章、分类、多级树结构、评论、共享文章、回收站、AI 接口
- `templates/`：页面模板（通用模板与分模块模板）
- `static/`：静态资源
- `media/`：用户上传文件（头像、文章图片等）

## 本地部署步骤

### 1) 准备环境
- Python 环境（建议虚拟环境）
- MySQL 服务正常可用

### 2) 安装依赖
```bash
pip install -r requirements.txt
```

### 3) 配置数据库
项目使用 `post_manager/settings.py` 中的 `DATABASES['default']` 配置 MySQL。

注意：当前仓库配置包含数据库密码等信息。实际使用时建议改为环境变量或本地未提交的配置。

### 4) 创建数据库（可选）
`create_db.py` 会基于 settings 中的连接信息创建数据库：
```bash
python create_db.py
```

### 5) 迁移数据库
```bash
python manage.py makemigrations
python manage.py migrate
```

### 6) 创建超级管理员
```bash
python manage.py createsuperuser
```

### 7) 启动服务
```bash
python manage.py runserver
```

## 主要路由（便于快速上手）
- 账号：
  - `/accounts/register/`
  - `/accounts/login/`
  - `/accounts/logout/`
  - `/accounts/index/`
  - `/accounts/user_info/`
  - `/accounts/content_moderation/`
  - `/accounts/favorites/`
- 文章：
  - `/article/list/`（文章列表 + 搜索/分类筛选）
  - `/article/create/`（创建）
  - `/article/edit/<pk>/`（编辑）
  - `/article/delete/<pk>/`（软删除到回收站）
  - `/article/trash/`（回收站列表）
  - `/article/trash/restore/<pk>/`（恢复）
  - `/article/trash/delete/<pk>/`（永久删除）
  - `/article/trash/empty/`（清空回收站）
  - `/article/categories/`（分类树管理）
  - `/article/share/<pk>/`（分享文章）
  - `/article/list_share/`（共享文章列表）
  - `/article/<pk>/summary/`、`/article/<pk>/statistical-summary/`（AI）

## 安全与生产注意事项
- 当前 `settings.py`：
  - `DEBUG=True`（开发环境建议关闭）
  - `SECRET_KEY` / `DEEPSEEK_API_KEY` 等敏感信息直接写在代码中（生产环境建议改为环境变量）
- 管理员能力较强（冻结账号、内容审核、永久删除），建议对生产部署进行最小权限控制与审计。

