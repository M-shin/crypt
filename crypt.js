#!/Users/mshin/.nvm/versions/node/v8.1.3/bin/node

'use strict';

const cla = require('command-line-args');
const clc = require('command-line-commands');
const clu = require('command-line-usage');
const colors = require('colors');
const crypto = require('crypto');
const fs = require('fs');
const json = require('jsonfile');
const pathx = require('path');
const prompt = require('prompt');
const { sprintf } = require('sprintf-js');

let state;
const statePath = pathx.join(__dirname, 'state.json');

const listFiles = () => {
  console.log(colors.black(sprintf('%-50s%-10s', 'Path', 'Hint')));

  Object.keys(state).sort().forEach(key => {
    console.log(sprintf('%-50s%-10s', key, state[key].hint));
  });
};

const encrypt = (input, output) => {
  const file = input.startsWith('/') ? input : pathx.join(__dirname, input);

  try {
    const text = fs.readFileSync(file);
    const promptSchema = {
      properties: {
        pass: {
          description: 'Password',
          type: 'string',
          hidden: true,
          replace: '.',
          required: true
        },
        hint: {
          description: 'Hint',
          type: 'string',
          hidden: false,
          required: false
        }
      }
    };

    prompt.get(promptSchema, (err, { pass, hint }) => {
      if (err) {
        throw err;
      }

      const cipher = crypto.createCipher('aes192', pass);
      let data = cipher.update(text, 'utf8', 'base64');
      data += cipher.final('base64');

      const hash = crypto.createHash('sha256');
      const passHash = hash.update(pass).digest('base64');

      state[output] = {
        data,
        hint,
        passHash
      };

      json.writeFileSync(statePath, state);
      console.log(`Successfully encrypted ${file} and stored in ${output}`);
    });
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
};

const promptPassword = (hint, next) => {
  let description = 'Password';
  if (hint) {
    description += ` (${hint})`;
  }

  const promptSchema = {
    properties: {
      pass: {
        description,
        type: 'string',
        hidden: true,
        replace: '.',
        required: true
      }
    }
  };

  prompt.get(promptSchema, next);
};

const verifyPassword = (originalHash, pass) => {
  const hash = crypto.createHash('sha256');
  const givenHash = hash.update(pass).digest('base64');

  if (givenHash !== originalHash) {
    console.error('Wrong password, exiting..');
    process.exit(1);
  }
};

const cat = path => {
  if (!state[path]) {
    console.log(`Could not find file: ${path}`);
    process.exit(1);
  }

  const { data, hint, passHash } = state[path];
  promptPassword(hint, (err, { pass }) => {
    if (err) {
      throw err;
    }

    verifyPassword(passHash, pass);

    const decipher = crypto.createDecipher('aes192', pass);
    let text = decipher.update(data, 'base64', 'utf8');
    text += decipher.final('utf8');

    console.log(text);
  });
};

const rm = path => {
  const { hint, passHash } = state[path];

  promptPassword(hint, (err, { pass }) => {
    if (err) {
      throw err;
    }

    verifyPassword(passHash, pass);

    delete state[path];
    json.writeFileSync(statePath, state);
    console.log(`Successfully deleted ${path}`);
  });
};

const mv = paths => {
  const { hint, passHash } = state[paths[0]];

  promptPassword(hint, (err, { pass }) => {
    if (err) {
      throw err;
    }

    verifyPassword(passHash, pass);

    state[paths[1]] = state[paths[0]];
    delete state[paths[0]];
    json.writeFileSync(statePath, state);
    console.log(`Successfully moved ${paths[0]} to ${paths[1]}`);
  });
};

const parseArgs = () => {
  const usage = () => {
    const config = [
      {
        header: 'Crypt CLI',
        content: 'CLI for accessing files stored inside crypt.'
      },
      {
        header: 'Commands',
        content: [
          {
            name: colors.red('ls'),
            summary: 'List files'
          },
          {
            name: colors.red('enc'),
            summary: 'Add a file'
          },
          {
            name: colors.red('cat'),
            summary: 'Print the contents of a file'
          },
          {
            name: colors.red('mv'),
            summary: 'Rename a file'
          },
          {
            name: colors.red('rm'),
            summary: 'Delete a file'
          }
        ]
      },
      {
        header: 'enc options',
        optionList: [
          {
            name: '--input',
            typeLabel: colors.gray('[underline]{file}'),
            description: 'The file to encrypt'
          },
          {
            name: '--output',
            typeLabel: colors.gray('[underline]{string}'),
            description: 'Where to store file inside crypt'
          }
        ]
      }
    ];

    console.log(clu(config));
    process.exit(0);
  };

  try {
    const commands = [null, 'ls', 'enc', 'cat', 'mv', 'rm'];
    const { command, argv } = clc(commands);
    if (command === 'ls') {
      listFiles();
    }

    if (command === 'enc') {
      const options = [
        {
          name: 'input',
          alias: 'i',
          type: String
        },
        {
          name: 'output',
          alias: 'o',
          type: String,
          defaultOption: true
        }
      ];

      const { input, output } = cla(options, { argv });
      if (!input || !output) {
        throw new Error();
      }

      encrypt(input, output);
    }

    if (command === 'cat') {
      const options = [
        {
          name: 'path',
          alias: 'p',
          type: String,
          defaultOption: true
        }
      ];

      const { path } = cla(options, { argv });
      if (!path) {
        throw new Error();
      }

      cat(path);
    }

    if (command === 'rm') {
      const options = [
        {
          name: 'path',
          alias: 'p',
          type: String,
          defaultOption: true
        }
      ];

      const { path } = cla(options, { argv });
      if (!path) {
        throw new Error();
      }

      rm(path);
    }

    if (command === 'mv') {
      const options = [
        {
          name: 'paths',
          alias: 'p',
          type: String,
          defaultOption: true,
          multiple: true
        }
      ];

      const { paths } = cla(options, { argv });
      if (!paths || paths.length !== 2) {
        throw new Error();
      }

      mv(paths);
    }

    if (command === null) {
      usage();
    }
  } catch (err) {
    usage();
  }
};

const setup = () => {
  state = json.readFileSync(statePath);

  prompt.message = '';
  prompt.start();
};

const main = () => {
  setup();
  parseArgs();
};

main();
