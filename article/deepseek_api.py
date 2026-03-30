# post_manager/article/deepseek_api.py
import requests
import hashlib
import time
import logging
from django.conf import settings
from django.core.cache import cache

# 获取配置，在 settings.py 中配置这些参数
DEEPSEEK_API_KEY = getattr(settings, 'DEEPSEEK_API_KEY', '')
DEEPSEEK_API_URL = getattr(settings, 'DEEPSEEK_API_URL', 'https://api.deepseek.com/v1/chat/completions')
API_TIMEOUT = getattr(settings, 'DEEPSEEK_API_TIMEOUT', 30)  # 请求超时时间（秒）
CACHE_TIMEOUT = getattr(settings, 'DEEPSEEK_CACHE_TIMEOUT', 60 * 60 * 24)  # 缓存时间（24小时）

# 配置日志
logger = logging.getLogger(__name__)


def generate_summary(text, max_length=300):
    """生成文章摘要"""
    if not text or not DEEPSEEK_API_KEY:
        return None

    # 生成基于文本内容的缓存键
    cache_key = f"deepseek_summary_{hashlib.md5(text.encode('utf-8')).hexdigest()}_{max_length}"
    cached_result = cache.get(cache_key)

    if cached_result:
        logger.info(f"从缓存获取摘要，key: {cache_key}")
        return cached_result

    try:
        # 调用API
        headers = {
            'Authorization': f'Bearer {DEEPSEEK_API_KEY}',
            'Content-Type': 'application/json'
        }
        data = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        f"请为以下文本生成一篇简明扼要的摘要，不超过{max_length}字：\n\n{text}"
                    )
                }
            ],
            "temperature": 0.3,  # 较低的温度值使输出更确定性
            "max_tokens": 500  # 限制最大token数量
        }

        start_time = time.time()
        response = requests.post(
            DEEPSEEK_API_URL,
            headers=headers,
            json=data,
            timeout=API_TIMEOUT
        )
        end_time = time.time()

        # 记录API调用时间
        logger.info(f"DeepSeek API调用耗时: {end_time - start_time:.2f}秒")

        if response.status_code == 200:
            result = response.json()['choices'][0]['message']['content']
            # 缓存结果
            cache.set(cache_key, result, CACHE_TIMEOUT)
            logger.info(f"成功生成摘要并缓存，key: {cache_key}")
            return result
        else:
            logger.error(f"API请求失败，状态码: {response.status_code}，响应内容: {response.text}")
            return None

    except Exception as e:
        logger.error(f"调用DeepSeek API时发生异常: {str(e)}", exc_info=True)
        return None


def generate_statistical_summary(text):
    """生成文章统计分析汇总"""
    if not text or not DEEPSEEK_API_KEY:
        return None

    # 生成基于文本内容的缓存键
    cache_key = f"deepseek_stats_{hashlib.md5(text.encode('utf-8')).hexdigest()}"
    cached_result = cache.get(cache_key)

    if cached_result:
        logger.info(f"从缓存获取统计汇总，key: {cache_key}")
        return cached_result

    try:
        # 调用API
        headers = {
            'Authorization': f'Bearer {DEEPSEEK_API_KEY}',
            'Content-Type': 'application/json'
        }
        data = {
            "model": "deepseek-chat",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "请对以下文本翻译为汉语（如果其为汉语翻译为英语）"
                        f"\n\n文本内容：{text}"
                    )
                }
            ],
            "temperature": 0.2,  # 更低的温度值使输出更专注和确定性
            "max_tokens": 1000  # 允许更长的输出
        }

        start_time = time.time()
        response = requests.post(
            DEEPSEEK_API_URL,
            headers=headers,
            json=data,
            timeout=API_TIMEOUT
        )
        end_time = time.time()

        # 记录API调用时间
        logger.info(f"DeepSeek API统计分析调用耗时: {end_time - start_time:.2f}秒")

        if response.status_code == 200:
            result = response.json()['choices'][0]['message']['content']
            # 缓存结果
            cache.set(cache_key, result, CACHE_TIMEOUT)
            logger.info(f"成功生成统计汇总并缓存，key: {cache_key}")
            return result
        else:
            logger.error(f"API请求失败，状态码: {response.status_code}，响应内容: {response.text}")
            return None

    except Exception as e:
        logger.error(f"调用DeepSeek API时发生异常: {str(e)}", exc_info=True)
        return None


def split_text_into_chunks(text, chunk_size=4000, overlap=200):
    """
    将长文本分割成多个重叠的小块，适合处理超长文本
    返回：文本块列表
    """
    if len(text) <= chunk_size:
        return [text]

    chunks = []
    start = 0

    while start < len(text):
        end = min(start + chunk_size, len(text))

        # 如果不是最后一块，尝试在句号、问号或感叹号处分割
        if end < len(text):
            # 寻找最近的句号、问号或感叹号
            for punct in ['. ', '? ', '! ', '\n\n']:
                pos = text[start:end].rfind(punct)
                if pos != -1:
                    end = start + pos + len(punct)
                    break

        chunks.append(text[start:end])
        start = end - overlap  # 创建重叠区域，确保内容连贯性

    return chunks


def generate_summary_for_long_text(text, max_length=300):
    """为超长文本生成摘要（自动分割处理）"""
    if len(text) < 4000:  # 如果文本不长，直接调用常规摘要函数
        return generate_summary(text, max_length)

    # 分割文本
    chunks = split_text_into_chunks(text)
    logger.info(f"长文本已分割为 {len(chunks)} 块")

    # 为每个块生成摘要
    chunk_summaries = []
    for i, chunk in enumerate(chunks):
        logger.info(f"正在处理第 {i + 1}/{len(chunks)} 块")
        chunk_summary = generate_summary(chunk, max_length=200)
        if chunk_summary:
            chunk_summaries.append(chunk_summary)

    # 将所有块的摘要合并，并生成最终摘要
    combined_summary = "\n\n".join(chunk_summaries)
    logger.info(f"合并所有块摘要，总长度: {len(combined_summary)}")

    # 生成最终摘要
    final_summary = generate_summary(combined_summary, max_length=max_length)
    return final_summary