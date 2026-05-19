buildPlugin(
    useContainerAgent: true,
    tests: [skip: true],
    skipTests: true,
    configurations: [
        [platform: 'linux', jdk: 21],
        [platform: 'windows', jdk: 21]
    ],
    spotbugs: [
        qualityGates: [
            [
                threshold: 1000,
                type: 'TOTAL',
                unstable: false
            ]
        ]
    ]
)
