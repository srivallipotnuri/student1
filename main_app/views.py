import json
import requests
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render, reverse
from django.views.decorators.csrf import csrf_exempt

from .EmailBackend import EmailBackend
from .models import Attendance, Session, Subject

import threading
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from .utils import generate_token
from django.core.mail import EmailMessage
from django.conf import settings
from .models import CustomUser

# Create your views here.


class EmailThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


def send_activation_email(user, request):
    current_site = get_current_site(request)
    email_subject = 'Activate your account'
    email_body = render_to_string('main_app/activate.html', {
        'user': user,
        'domain': current_site,
        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
        'token': generate_token.make_token(user)
    })

    email = EmailMessage(subject=email_subject, body=email_body,
                         from_email=settings.EMAIL_FROM_USER,
                         to=[user.email]
                         )

    # if not settings.TESTING:
    EmailThread(email).start()

def login_page(request):
    if request.user.is_authenticated:
        if request.user.user_type == '1':
            return redirect(reverse("admin_home"))
        elif request.user.user_type == '2':
            
            return redirect(reverse("staff_home"))
        else:
            return redirect(reverse("student_home"))
    return render(request, 'main_app/login.html')


def doLogin(request, **kwargs):
    if request.method != 'POST':
        return HttpResponse("<h4>Denied</h4>")
    else:
        #Google recaptcha
        captcha_token = request.POST.get('g-recaptcha-response')
        captcha_url = "https://www.google.com/recaptcha/api/siteverify"
        captcha_key = "6LfswtgZAAAAABX9gbLqe-d97qE2g1JP8oUYritJ"
        data = {
            'secret': captcha_key,
            'response': captcha_token
        }
        # Make request
        try:
            captcha_server = requests.post(url=captcha_url, data=data)
            response = json.loads(captcha_server.text)
            if response['success'] == False:
                messages.error(request, 'Invalid Captcha. Try Again')
                return redirect('/')
        except:
            messages.error(request, 'Captcha could not be verified. Try Again')
            return redirect('/')
        
        if request.method == 'POST':
            context = {'data': request.POST}
            username = request.POST.get('email')
            password = request.POST.get('password')
        # Authenticate
        user = EmailBackend.authenticate(request, username=username, password=password)
        if user.user_type == '1':
            if user!=None:
                login(request, user)
                messages.add_message(request, messages.SUCCESS,
                                     f'Welcome {user.username}')
                return redirect(reverse("admin_home"))
        else:
            if user.user_type == '2' or user.user_type == '3':
                if user and not user.is_email_verified:
                    messages.add_message(request, messages.ERROR,
                                            'Email is not verified, please check your email inbox')
                    return render(request, 'main_app/login.html', context, status=401)

                if not user:
                    messages.add_message(request, messages.ERROR,
                                            'Invalid credentials, try again')
                    return render(request, 'main_app/login.html', context, status=401)
                if user.is_email_verified:
                    messages.add_message(request, messages.ERROR,
                                            'Email is already verified, please login')
                    return render(request, 'main_app/login.html', context, status=401)
                if user.user_type == '2':
                    login(request, user)
                    messages.add_message(request, messages.SUCCESS,
                                         f'Welcome {user.username}')
                    return redirect(reverse("staff_home"))
                else:
                    messages.add_message(request, messages.SUCCESS,
                                         f'Welcome {user.username}')
                    return redirect(reverse("student_home"))
            else:
                messages.add_message(request, messages.ERROR,
                                     'Invalid credentials, try again')
                return render(request, 'main_app/login.html', context, status=401)

        # if user != None:
        #     login(request, user)
        #     if user.user_type == '1':
        #         messages.add_message(request, messages.SUCCESS,
        #                                 f'Welcome {user.username}')
        #         return redirect(reverse("admin_home"))
        #     elif user.user_type == '2':
        #         messages.add_message(request, messages.SUCCESS,
        #                                 f'Welcome {user.username}')
        #         return redirect(reverse("staff_home"))
        #     else:
        #         messages.add_message(request, messages.SUCCESS,
        #                                 f'Welcome {user.username}')
        #         return redirect(reverse("student_home"))
        # else:
        #     messages.error(request, "Invalid details")
        #     return redirect("/")



def logout_user(request):
    if request.user != None:
        logout(request)
    return redirect("/")


@csrf_exempt
def get_attendance(request):
    subject_id = request.POST.get('subject')
    session_id = request.POST.get('session')
    try:
        subject = get_object_or_404(Subject, id=subject_id)
        session = get_object_or_404(Session, id=session_id)
        attendance = Attendance.objects.filter(subject=subject, session=session)
        attendance_list = []
        for attd in attendance:
            data = {
                    "id": attd.id,
                    "attendance_date": str(attd.date),
                    "session": attd.session.id
                    }
            attendance_list.append(data)
        return JsonResponse(json.dumps(attendance_list), safe=False)
    except Exception as e:
        return None


def activate_user(request, uidb64, token):

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))

        user = CustomUser.objects.get(pk=uid)

    except Exception as e:
        user = None

    if user and generate_token.check_token(user, token):
        user.is_email_verified = True
        user.save()

        messages.add_message(request, messages.SUCCESS,
                             'Email verified, you can now login')
        return redirect(reverse('login_page'))

    return render(request, 'main_app/activate-failed.html', {"user": user})


def showFirebaseJS(request):
    data = """
    // Give the service worker access to Firebase Messaging.
// Note that you can only use Firebase Messaging here, other Firebase libraries
// are not available in the service worker.
importScripts('https://www.gstatic.com/firebasejs/7.22.1/firebase-app.js');
importScripts('https://www.gstatic.com/firebasejs/7.22.1/firebase-messaging.js');

// Initialize the Firebase app in the service worker by passing in
// your app's Firebase config object.
// https://firebase.google.com/docs/web/setup#config-object
firebase.initializeApp({
    apiKey: "AIzaSyBarDWWHTfTMSrtc5Lj3Cdw5dEvjAkFwtM",
    authDomain: "sms-with-django.firebaseapp.com",
    databaseURL: "https://sms-with-django.firebaseio.com",
    projectId: "sms-with-django",
    storageBucket: "sms-with-django.appspot.com",
    messagingSenderId: "945324593139",
    appId: "1:945324593139:web:03fa99a8854bbd38420c86",
    measurementId: "G-2F2RXTL9GT"
});

// Retrieve an instance of Firebase Messaging so that it can handle background
// messages.
const messaging = firebase.messaging();
messaging.setBackgroundMessageHandler(function (payload) {
    const notification = JSON.parse(payload);
    const notificationOption = {
        body: notification.body,
        icon: notification.icon
    }
    return self.registration.showNotification(payload.notification.title, notificationOption);
});
    """
    return HttpResponse(data, content_type='application/javascript')
