{
  'targets': [
    {
      'target_name': 'libscep',
      'type': 'shared_library',
      'sources': [
        'lib.cc'
      ],
     'link_settings': {
          'libraries': [
            '-lcrypto'
          ],
            'include_dirs': [
              '../openssl0.9.8/include'
              '/usr/include',
            ],
      }
    },
    {
      'target_name': 'scep',
      'sources': [
        'scep.cc'
      ],
     'link_settings': {
          'libraries': [
        '-ldl'
          ],
            'include_dirs': [
              '/usr/include',
            ],
      }
    }
  ]
}
