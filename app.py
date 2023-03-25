#!/usr/bin/env python3
import os

import aws_cdk as cdk

from expediate.expediate_stack import ExpediateStack

app = cdk.App()

ExpediateStack(
    app, 'ExpediateStack',
    env = cdk.Environment(
        account = os.getenv('CDK_DEFAULT_ACCOUNT'),
        region = os.getenv('CDK_DEFAULT_REGION')
    ),
    synthesizer = cdk.DefaultStackSynthesizer(
        qualifier = '4n6ir'
    )
)

cdk.Tags.of(app).add('Alias','ALL')
cdk.Tags.of(app).add('GitHub','https://github.com/4n6ir/expediate.git')

app.synth()
