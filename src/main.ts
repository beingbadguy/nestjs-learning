import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  try {
    const app = await NestFactory.create(AppModule);

    // enable the global validation pipe
    app.useGlobalPipes(
      new ValidationPipe({
        whitelist: true, // extra fields remove karega
        forbidNonWhitelisted: true, // agar unknown field bhejega toh error throw karega
        transform: true, // payloads ko DTO class instances mein convert karega
      }),
    );
    await app.listen(process.env.PORT ?? 3000);

    console.log(`🔗 Server is running on port ${await app.getUrl()}`);
  } catch ({ error }) {
    console.error('❌ Error during application bootstrap:', error);
    process.exit(1);
  }
}
bootstrap();
