{% if config.theme %}
    {% if config.theme == 'system' %}
        <style>
            @import "{{ cb_url('light-theme.css') }}" screen;
            @import "{{ cb_url('dark-theme.css') }}" screen and (prefers-color-scheme: dark);
        </style>
    {% else %}
        <link rel="stylesheet" href="{{ cb_url(config.theme + '-theme.css') }}"/>
    {% endif %}
{% else %}
    <link rel="stylesheet" href="{{ cb_url(('dark' if config.dark else 'light') + '-theme.css') }}"/>
{% endif %}
<link rel="stylesheet" href="{{ cb_url('main.css') }}">
<link rel="stylesheet" href="{{ cb_url('error.css') }}">
<style>{{ config.style }}</style>
<div>
    <h1>Error</h1>
    <p>
        {{ error_message|safe }}
    </p>
    <hr>
    <p>
    {% if blocked is defined %}
        <h4><a class="link" href="https://farside.link">{{ translation['continue-search'] }}</a></h4>
        Whoogle:
        <br>
        <a class="link-color" href="{{farside}}/whoogle/search?q={{query}}{{params}}">
            {{farside}}/whoogle/search?q={{query}}{{params}}
        </a>
        <br><br>
        Searx:
        <br>
        <a class="link-color" href="{{farside}}/searx/search?q={{query}}">
            {{farside}}/searx/search?q={{query}}
        </a>
        <hr>
    {% endif %}
    </p>
    <a class="link" href="home">Return Home</a>
</div>
