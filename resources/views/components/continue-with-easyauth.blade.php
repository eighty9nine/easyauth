@props([
    'href' => route('sso.login'),
    'label' => 'Continue with Easy Auth',
])

<a
    href="{{ $href }}"
    {{ $attributes->merge(['class' => 'inline-flex w-full items-center justify-center gap-2 rounded-lg bg-[#D45500] px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-[#B94700] focus:outline-none focus:ring-2 focus:ring-[#D45500]/30 focus:ring-offset-2']) }}
>
    <span>{{ $label }}</span>
</a>
