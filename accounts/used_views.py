# myapp/views.py
from captcha.models import CaptchaStore
from django.contrib import messages
from django.contrib.auth import login, authenticate
from django.shortcuts import render, get_object_or_404, redirect,HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from .forms import RegisterForm, LoginForm,UserForm, BankCardForm,RechargeForm,TransactionForm,PasswordVerifyForm
from .models import RechargeRecord, ConsumptionRecord,BankCard, User,BankCards,Transaction
from django import forms
from django.db.models import Q


from .code import check_code
from io import BytesIO
from PIL import ImageFont

def image_code(request):
    """ 生成图片验证码 """
    img, code_string = check_code()
    
    request.session["image_code"] = code_string
    request.session.set_expiry(60)

    stream = BytesIO()
    img.save(stream, 'png')
    stream.getvalue()

    return HttpResponse(stream.getvalue())


# 注册

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        # 获取用户提交的验证码
        user_submitted_code = request.POST.get('image_code')
        # 验证验证码是否正确
        if user_submitted_code != request.session.get('image_code', ''):
            messages.error(request, '验证码错误，请重试。')
            return render(request, 'register.html', {'form': form})
        
        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data['password1'])
            user.save()
            login(request, user)
            messages.success(request, '注册成功！欢迎加入我们。')
            return redirect('login')
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})


# 登录

def login_view(request):
    if request.method == 'POST':
        form = LoginForm(data=request.POST)
         # 获取用户提交的验证码
        user_submitted_code = request.POST.get('image_code')
        # 验证验证码是否正确
        if user_submitted_code != request.session.get('image_code', ''):
            messages.error(request, '验证码错误，请重试。')
            return render(request, 'register.html', {'form': form})
        
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'],
                                password=form.cleaned_data['password'])
            if user is not None:
                login(request, user)
                return redirect('home')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})


# 主页面
@login_required
def home(request):
    recharges = RechargeRecord.objects.filter(user=request.user)
    consumptions = ConsumptionRecord.objects.filter(user=request.user)
    return render(request, 'home.html', {
        'recharges': recharges,
        'consumptions': consumptions,
        'account_balance': request.user.account_balance,
        # 从上下文中移除 transaction_view
    })
   

# 消费记录
@login_required
def consume(request):
    if request.method == 'POST':
        amount = request.POST.get('amount')
        if amount:
            if request.user.account_balance >= float(amount):
                ConsumptionRecord.objects.create(user=request.user, amount=amount)
                request.user.account_balance -= float(amount)
                request.user.save()
            else:
                return render(request, 'error.html', {'error_message': 'Insufficient funds'})
            return redirect('home')
    return redirect('home')

# 注销
@login_required
def user_logout(request):
    # 调用Django的logout函数来注销用户
    logout(request)
    # 注销后重定向到首页
    return redirect('home')  

@login_required
def user_data_view(request, user_id):
    user = get_object_or_404(User, id=user_id)
    bank_card = BankCard.objects.filter(user=user_id).first()

    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=user)
        bank_card_form = BankCardForm(request.POST, instance=bank_card)
        
        if user_form.is_valid() and bank_card_form.is_valid():
            user_form.save()
            bank_card_form.save()
            return redirect('user_data', user_id=user_id)
    else:
        user_form = UserForm(instance=user)
        bank_card_form = BankCardForm(instance=bank_card)

    consumption_records = ConsumptionRecord.objects.filter(user=user)
    recharge_records = RechargeRecord.objects.filter(user=user)


    return render(request, 'user_data.html', {
        'user': user,
        'user_form': user_form,
        'bank_card_form': bank_card_form,
        'consumption_records': consumption_records,
        'recharge_records': recharge_records,
        'bank_card': bank_card,
    })

@login_required
def user_data_update2(request, user_id):
    user = get_object_or_404(User, id=user_id)
    bank_card = BankCard.objects.filter(user=user).first()
    
    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=user)
        bank_card_form = BankCardForm(request.POST)
        
        if user_form.is_valid() and bank_card_form.is_valid():
            user_instance = user_form.save()
            # 如果 bank_card 不存在，则创建新的 BankCard 实例
            if not bank_card:
                bank_card = BankCard(user=user_instance)
                bank_card.card_number = bank_card_form.cleaned_data['card_number']
            else:
                bank_card.card_number = bank_card_form.cleaned_data['card_number']
            # 检查银行卡号是否已经存在于BankCards数据库中
            existing_card = BankCards.objects.filter(card_number=bank_card.card_number).first()
            if existing_card:
                #检查银行卡号是否已经存在于BankCard数据库中
                existing_card2 = BankCard.objects.filter(card_number=bank_card.card_number).first()
                if existing_card2:
                    # 如果银行卡号已存在，提示用户
                    bank_card_form.add_error('card_number', forms.ValidationError('该银行卡号已存在。'))
                else:
                    bank_card.save()
            else:
                bank_card_form.add_error('card_number', forms.ValidationError('该银行卡号不存在。'))
            return redirect('user_data', user_id=user_id)
    else:
        if bank_card:
            bank_card_form = BankCardForm(instance=bank_card)
        else:
            bank_card_form = BankCardForm()

    return render(request, 'user_data.html', {
        'user': user,
        'user_form': user_form,
        'bank_card_form': bank_card_form,
    })
    
@login_required
def user_data_update(request, user_id):
    user = get_object_or_404(User, id=user_id)
    bank_card = BankCard.objects.filter(user=user).first()

    if request.method == 'POST':
        user_form = UserForm(request.POST, instance=user)
        bank_card_form = BankCardForm(request.POST)

        if user_form.is_valid() and bank_card_form.is_valid():
            user_instance = user_form.save()

            # 获取用户输入的银行卡号
            card_number = bank_card_form.cleaned_data['card_number']

            # 检查银行卡号是否存在于总银行卡库BankCards中
            existing_card = BankCards.objects.filter(card_number=card_number).first()
            if existing_card:
                # 检查银行卡号是否已经存在于BankCard表中
                existing_bank_card = BankCard.objects.filter(card_number=card_number).first()
                if existing_bank_card:
                    # 如果银行卡号已存在，提示用户
                    bank_card_form.add_error('card_number', forms.ValidationError('该银行卡号已存在。'))
                else:
                    # 如果银行卡号不存在BankCard表中，从总银行卡库添加到BankCard表中
                    if not bank_card:
                        bank_card = BankCard.objects.create(user=user_instance, card_number=card_number)
                        bank_card.balance = existing_card.balance  # 同步余额
                        bank_card.save()
                    else:
                        bank_card.card_number = card_number
                        bank_card.balance = existing_card.balance  # 同步余额
                        bank_card.save()
            else:
                # 如果银行卡号不存在于总银行卡库，提示用户
                bank_card_form.add_error('card_number', forms.ValidationError('该银行卡不存在。'))

             # 成功保存后，重定向到home页面
            return redirect('home')
    else:
        if bank_card:
            bank_card_form = BankCardForm(instance=bank_card)
        else:
            bank_card_form = BankCardForm()
        
    return redirect('home')

# 充值成功
def success_view(request):
    return render(request, 'success.html')

# 充值
@login_required
def recharge(request, user_id):
    user = get_object_or_404(User, id=user_id)
    
    # 获取用户关联的 BankCard 实例
    bank_card = user.bank_card
    
    if not bank_card:
        # 如果用户没有关联的银行卡，可以重定向到添加银行卡的页面或显示错误信息
        return render(request, 'no_bank_card.html')
    
    if request.method == 'POST':
        recharge_form = RechargeForm(request.POST)
        
        #处理密码验证表单
        password_form = PasswordVerifyForm(request.POST)      
        
        if recharge_form.is_valid()and password_form.is_valid():
            amount = recharge_form.cleaned_data['amount']
            password = password_form.cleaned_data['password']
            # 验证用户密码是否正确
            if authenticate(request, username=user.username, password=password):
                # 更新 BankCards 中的 balance
                bank_card_balance = BankCards.objects.get(card_number=bank_card.card_number)
                bank_card_balance.balance += amount
                bank_card_balance.save()
                
                # 更新 BankCard 中的 balance（如果需要）
                bank_card.balance += amount
                bank_card.save()
                
                # 重定向到成功页面或显示成功信息
                return redirect('success_view')
            else:
                # 密码错误，显示错误信息
                messages.error(request, '密码错误，请重试。')
    else:
        recharge_form = RechargeForm()
        password_form = PasswordVerifyForm()
    
    return render(request, 'recharge.html', {
        'user': user,
        'bank_card': bank_card,
        'recharge_form': recharge_form,
        'password_form': password_form,  # 添加密码验证表单到上下文
    })

# 交易
@login_required
def transaction_view(request):
    if request.method == 'POST':
        transaction_form = TransactionForm(request.POST)
        
        if transaction_form.is_valid():
            payer_card_number = transaction_form.cleaned_data['payer_card_number']
            payee_card_number = transaction_form.cleaned_data['payee_card_number']
            amount = transaction_form.cleaned_data['amount']
            description = transaction_form.cleaned_data['description']

            # 获取付款方和收款方的银行卡实例
            payer_card = get_object_or_404(BankCards, card_number=payer_card_number)
            payee_card = get_object_or_404(BankCards, card_number=payee_card_number)
            
            payer_card2 = get_object_or_404(BankCard, card_number=payer_card_number)
            payee_card2 = get_object_or_404(BankCard, card_number=payee_card_number)
            
            # 检查付款方余额是否足够
            if payer_card.balance < amount:
                # 余额不足，返回错误信息
                transaction_form.add_error(None, forms.ValidationError('余额不足，交易失败。'))
                return render(request, 'transaction.html', {'form': transaction_form})

            # 更新付款方和收款方的余额
            payer_card.balance -= amount
            payee_card.balance += amount
            payer_card.save()
            payee_card.save()           
            payer_card2.balance -= amount
            payee_card2.balance += amount
            payer_card2.save()
            payee_card2.save()          
            # 创建交易记录
            transaction = Transaction.objects.create(
                payer_card_number=payer_card_number,
                payee_card_number=payee_card_number,
                amount=amount,
                description=description
            )

            # 重定向到交易成功页面或显示交易成功信息
            return redirect('home')
    else:
        transaction_form = TransactionForm()

    return render(request, 'transaction.html', {'form': transaction_form})

# 显示用户交易记录
@login_required
def user_transactions_view(request,user_id):
    user = get_object_or_404(User, id=user_id)
    # 获取用户关联的 BankCard 实例
    bank_card = user.bank_card
    user_card_number = bank_card.card_number if bank_card else None

    # 查询所有与用户银行卡号相关的交易记录
    if user_card_number:
        # 查询所有与用户银行卡号相关的交易记录
        transactions = Transaction.objects.filter(
            Q(payer_card_number=user_card_number) | Q(payee_card_number=user_card_number)
        ).order_by('-transaction_date')  # 按交易日期降序排列
    else:
        transactions = Transaction.objects.none()  # 如果用户没有银行卡号，则不显示任何交易记录

    return render(request, 'user_transactions.html', {'transactions': transactions})

''' 
    return render(request, 'user_data.html', {
        'user': user,
        'user_form': user_form,
        'bank_card_form': bank_card_form,
    })
''' 


from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from decimal import Decimal
import json
import base64

'''
@csrf_exempt  # 禁用CSRF令牌验证（仅用于示例，实际项目中应谨慎处理CSRF）
def GetPay(request):
    """ 接口 """
    if request.method == 'POST':
        # 获取JSON数据
        data = json.loads(request.body)
        # 从文件加载私钥
        with open('myapp/keys/private_key.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())
        
        # 创建一个PKCS1_OAEP对象用于解密
        cipher_rsa = PKCS1_OAEP.new(private_key)
        
        # 解密接收到的数据
        decrypted_data = {}
        for key, value in data.items():
            # Base64解码然后解密每个值
            encrypted_value = base64.b64decode(value)
            # 解密每个值
            decrypted_value = cipher_rsa.decrypt(encrypted_value)
            decrypted_data[key] = decrypted_value.decode()  # 假设解密后的数据是字符串，进行解码
        print(decrypted_data)
        
        res = transaction_view2(decrypted_data)
        print(res)
        # 处理数据...
        # 假设我们简单地返回接收到的数据
        response_data = res
        
        with open('myapp/key/public_key.pem','rb') as f:
            public_key = RSA.import_key(f.read())
        
        # 创建一个PKCS1_OAEP对象用于加密
        cipher_rsa = PKCS1_OAEP.new(public_key)
        
        # 加密响应数据
        encrypted_res = {}
        for key, value in response_data.items():
            # 确保值是字符串类型，然后编码为字节串进行加密
            if isinstance(value, int):  # 如果值是整数，先转换为字符串
                value = str(value)
            encrypted_value = cipher_rsa.encrypt(value.encode())
            encrypted_res[key] = base64.b64encode(encrypted_value).decode()
        
        # 返回JSON响应
        return JsonResponse(encrypted_res)
    else:
        print('请求失败')

'''

@csrf_exempt  # 禁用CSRF令牌验证（仅用于示例，实际项目中应谨慎处理CSRF）
def GetPay(request):
    """ 接口 """
    if request.method == 'POST':
        # 获取JSON数据
        data = json.loads(request.body)
        
        print(data)
        
        # 提取签名
        signature = base64.b64decode(data.pop('signature'))
        
        # 从文件加载公钥
        with open('myapp/key/public_key.pem', 'rb') as f:
            public_key = RSA.import_key(f.read())
        
        # 创建一个PKCS1_v1_5对象用于验证签名
        pkcs1_15_obj = pkcs1_15.new(public_key)
        
        print(data)
        
        # 计算哈希值
        hash = SHA256.new(json.dumps(data, sort_keys=True).encode())
        
        # 验证签名
        try:
            pkcs1_15_obj.verify(hash, signature)
            print('签名验证成功')
        except (ValueError, TypeError) as e:
            print('签名验证失败:', e)
            return JsonResponse({'error': '签名验证失败'}, status=400)
        
         # 从文件加载私钥
        with open('myapp/keys/private_key.pem', 'rb') as f:
            private_key = RSA.import_key(f.read())
        
        # 创建一个PKCS1_OAEP对象用于解密
        cipher_rsa = PKCS1_OAEP.new(private_key)
        
        # 解密接收到的数据
        decrypted_data = {}
        for key, value in data.items():
            if key != "signature":  # 跳过签名字段
                # Base64解码然后解密每个值
                encrypted_value = base64.b64decode(value)
                # 解密每个值
                decrypted_value = cipher_rsa.decrypt(encrypted_value)
                decrypted_data[key] = decrypted_value.decode()  # 假设解密后的数据是字符串，进行解码
        print(decrypted_data)
        
        res = transaction_view2(decrypted_data)
        print(res)
        # 处理数据...

        response_data = res
        
        with open('myapp/key/public_key.pem','rb') as f:
            public_key = RSA.import_key(f.read())
        
        # 创建一个PKCS1_OAEP对象用于加密
        cipher_rsa = PKCS1_OAEP.new(public_key)
        
        # 加密响应数据
        encrypted_res = {}
        for key, value in response_data.items():
            # 确保值是字符串类型，然后编码为字节串进行加密
            if isinstance(value, int):  # 如果值是整数，先转换为字符串
                value = str(value)
            encrypted_value = cipher_rsa.encrypt(value.encode())
            encrypted_res[key] = base64.b64encode(encrypted_value).decode()
        
        # 返回JSON响应
        return JsonResponse(encrypted_res)
    else:
        print('请求失败')

def transaction_view2(data):
        

        # 获取付款方和收款方的银行卡实例
        payer_card = get_object_or_404(BankCards, card_number=data["from"])
        payee_card = get_object_or_404(BankCards, card_number=data["to"])
        
        payer_card2 = get_object_or_404(BankCard, card_number=data["from"])
        payee_card2 = get_object_or_404(BankCard, card_number=data["to"])
        
        amount = data["price"]
        amount = Decimal(amount)
        # 检查付款方余额是否足够
        if payer_card.balance < amount:
            # 余额不足，返回错误信息
            response_data = {
                "status": "error",
                "message": "余额不足，交易失败。"
            }
            return response_data

        # 更新付款方和收款方的余额
        payer_card.balance -= amount
        payee_card.balance += amount
        payer_card.save()
        payee_card.save()           
        payer_card2.balance -= amount
        payee_card2.balance += amount
        payer_card2.save()
        payee_card2.save()          
        # 创建交易记录
        transaction = Transaction.objects.create(
            payer_card_number=payer_card.card_number,
            payee_card_number=payee_card.card_number,
            amount=amount,
            description="none"
        )
        

        # 重定向到交易成功页面或显示交易成功信息
        response_data = {
            "status": "success",
            "message": "交易成功。"
        }
        return response_data
    
