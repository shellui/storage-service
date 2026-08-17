from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.shortcuts import redirect, render
from django.urls import reverse


class InitialSuperuserForm(forms.Form):
    username = forms.CharField(
        max_length=150,
        widget=forms.TextInput(attrs={'placeholder': 'admin'}),
    )
    email = forms.EmailField(
        required=False,
        widget=forms.EmailInput(attrs={'placeholder': 'admin@example.com'}),
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Create a strong password'})
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Repeat password'})
    )

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        username = cleaned_data.get('username')
        email = cleaned_data.get('email')
        if password and password_confirm and password != password_confirm:
            self.add_error('password_confirm', 'Passwords do not match.')

        if password:
            user_model = get_user_model()
            user = user_model(username=username or '', email=email or '')
            try:
                validate_password(password, user=user)
            except ValidationError as exc:
                self.add_error('password', exc)
        return cleaned_data


def root(request):
    user_model = get_user_model()
    has_users = user_model._default_manager.exists()
    form = InitialSuperuserForm(request.POST or None)

    if request.method == 'POST':
        if has_users:
            return redirect('root')

        if form.is_valid():
            try:
                with transaction.atomic():
                    if user_model._default_manager.exists():
                        form.add_error(
                            None,
                            'A user was created in another session. Setup has already been completed.',
                        )
                    else:
                        user_model._default_manager.create_superuser(
                            username=form.cleaned_data['username'],
                            email=form.cleaned_data['email'],
                            password=form.cleaned_data['password'],
                        )
                        return redirect(f"{reverse('root')}?setup=done")
            except IntegrityError:
                form.add_error(
                    'username',
                    'This username is already in use. Please choose another one.',
                )
            except Exception:
                form.add_error(
                    None,
                    'We could not create the initial user right now. Please retry in a moment.',
                )

    context = {
        'form': form,
        'show_setup_form': not user_model._default_manager.exists(),
        'swagger_url': reverse('swagger-ui'),
        'redoc_url': reverse('redoc'),
        'schema_url': reverse('schema'),
        'version': settings.VERSION,
        'setup_done': request.GET.get('setup') == 'done',
    }
    return render(request, 'home.html', context)
