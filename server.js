const http = require('http');
const path = require('path');
const Koa = require('koa');
const cors = require('koa2-cors');
const koaBody = require('koa-body');
const koaStatic = require('koa-static');
const Router = require('koa-router');
const passport = require('koa-passport');
const { Strategy } = require('passport-http-bearer');
const bcrypt = require('bcrypt');
const faker = require('faker');
const { v4: uuidv4 } = require('uuid');

const app = new Koa();

app.use(
  cors({
    origin: '*',
    credentials: true,
    'Access-Control-Allow-Origin': true,
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE'],
  }),
);

app.use(koaBody({
  text: true,
  urlencoded: true,
  multipart: true,
  json: true,
}));

const dirPublic = path.join(__dirname, '/public');
app.use(koaStatic(dirPublic));

faker.locale = 'ru';

const tokens = new Map();
const users = new Map();
const rounds = 10;

users.set('vasya', {
  id: uuidv4(), login: 'vasya', name: 'Vasya', password: bcrypt.hashSync('password', rounds), avatar: 'https://i.pravatar.cc/40',
});

const news = [
  {
    id: uuidv4(),
    title: faker.lorem.words(),
    image: 'https://placeimg.com/640/480/nature',
    content: faker.lorem.paragraph(),
  },
  {
    id: uuidv4(),
    title: faker.lorem.words(),
    image: 'https://placeimg.com/640/480/arch',
    content: faker.lorem.paragraph(),
  },
  {
    id: uuidv4(),
    title: faker.lorem.words(),
    image: 'https://placeimg.com/640/480/tech',
    content: faker.lorem.paragraph(),
  },
  {
    id: uuidv4(),
    title: faker.lorem.words(),
    image: 'https://placeimg.com/640/480/sepia',
    content: faker.lorem.paragraph(),
  },
];

passport.use(new Strategy((token, callback) => {
  const user = tokens.get(token);
  if (user === undefined) {
    return callback(null, false);
  }

  return callback(null, user);
}));
const bearerAuth = passport.authenticate('bearer', { session: false });

const router = new Router();

router.post('/auth', async (ctx) => {
  const { login, password } = ctx.request.body;

  const user = users.get(login);
  if (user === undefined) {
    ctx.response.status = 400;
    ctx.response.body = { message: 'Пользователь не найден' };
    return;
  }

  const result = await bcrypt.compare(password, user.password);
  if (result === false) {
    ctx.response.status = 400;
    ctx.response.body = { message: 'неверный пароль' };
    return;
  }

  const token = uuidv4();
  tokens.set(token, user);
  ctx.response.body = { token };
});

router.use('/private', bearerAuth);
router.get('/private/me', async (ctx) => {
  const { user } = ctx.state;
  ctx.response.body = {
    id: user.id, login: user.login, name: user.name, avatar: user.avatar,
  };
});
router.get('/private/news', async (ctx) => {
  ctx.response.body = news;
});

router.get('/private/news/:id', async (ctx) => {
  const [item] = news.filter((o) => o.id === ctx.params.id);
  if (item === undefined) {
    ctx.response.status = 404;
    ctx.response.body = { message: 'ничего не найдено' };
    return;
  }
  ctx.response.body = item;
});

app.use(router.routes()).use(router.allowedMethods());

const port = process.env.PORT || 7878;
const server = http.createServer(app.callback());

// eslint-disable-next-line no-console
server.listen(port, () => console.log('Server started'));
