package ru.javabegin.micro.planner.users.mq.func;

import lombok.Getter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.Message;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Sinks;
import reactor.util.concurrent.Queues;

import java.util.function.Supplier;


// описываются все каналы с помощью функциональных методов

@Configuration // spring считывает бины и создает соотв. каналы
@Getter
public class MessageFunc {

    // для того, чтобы считывать данные по требованию (а не постоянно) - создаем поток, откуда данные будут отправляться уже в канал SCS
    // будем исп внутренную шину, из которой будут отправляться сообщения в канал SCS (по требованию)
    private Sinks.Many<Message<Long>> innerBus = Sinks.many().multicast().onBackpressureBuffer(Queues.SMALL_BUFFER_SIZE, false);


    // отправляет в канал id пользователя, для которого нужно создать тестовые данные
    // название метода должно совпадать с настройками definition и bindings в файлах properties (или yml)
    @Bean
    public Supplier<Flux<Message<Long>>> newUserActionProduce() {
        return () -> innerBus.asFlux(); // будет считывать данные из потока Flux (как только туда попадают новые сообщения)
    }



}



