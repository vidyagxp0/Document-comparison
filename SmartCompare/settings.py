from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-mj7a)%-2#n$r81y$%!c8$5fv4-^-u6jlmq5x1idwjs*9-=vg75'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['89.116.21.165' ,'localhost', '127.0.0.1']

X_FRAME_OPTIONS = 'SAMEORIGIN'          # To embed oly same domain content in iframe or embed

# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'compareapp',
    'tailwind',
    'theme',
    'django_browser_reload',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    "django_browser_reload.middleware.BrowserReloadMiddleware",
]

ROOT_URLCONF = 'SmartCompare.urls'

CHATPDF_API_KEY = 'sec_svlzEoctoxWzXMSGAaPmbpJjX9z6bUrU'

CONVERT_API_SECRET = 'secret_LbeVcM0yXIDHWHHY'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'SmartCompare.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'smartcompare',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': 'localhost',  # Or your database host
        'PORT': '3306',       # Or your database port
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LOGIN_URL = 'login'

# SessionTimeExpity 
SESSION_COOKIE_AGE = 5 * 60 * 60

SESSION_EXPIRE_AT_BROWSER_CLOSE = True

SESSION_SAVE_EVERY_REQUEST = True

# Mail Configuration
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'quality@vidyagxp.com'
EMAIL_HOST_PASSWORD = 'ubhe xiui mhsp gjng'
DEFAULT_FROM_EMAIL = 'Document Comparison Coordinator'


# EMAIL_HOST_USER = 'adityapatel8912@gmail.com'
# EMAIL_HOST_PASSWORD = 'gqpibgqdoiutfews'
# DEFAULT_FROM_EMAIL = 'adityapatel8912@gmail.com'


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = '/static/'

STATIC_ROOT = BASE_DIR / 'staticfiles'

STATICFILES_DIRS = [
    BASE_DIR / "compareapp/static",
]

MEDIA_URL = '/media/'

MEDIA_ROOT = BASE_DIR / 'media'

TAILWIND_APP_NAME = 'theme'

# During Development not for Production
INTERNAL_IPS = [
    "127.0.0.1",
    "89.116.21.165"
]

NPM_BIN_PATH = "C:/Program Files/nodejs/npm.cmd"


# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
